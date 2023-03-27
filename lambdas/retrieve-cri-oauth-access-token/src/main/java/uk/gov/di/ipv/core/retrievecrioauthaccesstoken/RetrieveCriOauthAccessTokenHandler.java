package uk.gov.di.ipv.core.retrievecrioauthaccesstoken;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.message.StringMapMessage;
import software.amazon.lambda.powertools.logging.Logging;
import software.amazon.lambda.powertools.tracing.Tracing;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.auditing.AuditEvent;
import uk.gov.di.ipv.core.library.auditing.AuditEventTypes;
import uk.gov.di.ipv.core.library.auditing.AuditEventUser;
import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
import uk.gov.di.ipv.core.library.credentialissuer.CredentialIssuerService;
import uk.gov.di.ipv.core.library.credentialissuer.exceptions.CredentialIssuerException;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.dto.ClientSessionDetailsDto;
import uk.gov.di.ipv.core.library.dto.CredentialIssuerConfig;
import uk.gov.di.ipv.core.library.dto.CredentialIssuerSessionDetailsDto;
import uk.gov.di.ipv.core.library.dto.VisitedCredentialIssuerDetailsDto;
import uk.gov.di.ipv.core.library.exceptions.BadRequestError;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.core.library.exceptions.JourneyError;
import uk.gov.di.ipv.core.library.exceptions.SqsException;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.helpers.StepFunctionHelpers;
import uk.gov.di.ipv.core.library.kmses256signer.KmsEs256Signer;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;

import java.util.Map;

public class RetrieveCriOauthAccessTokenHandler
        implements RequestHandler<Map<String, String>, Map<String, Object>> {
    private static final Logger LOGGER = LogManager.getLogger();
    private final CredentialIssuerService credentialIssuerService;
    private final ConfigService configService;
    private final AuditService auditService;
    private final IpvSessionService ipvSessionService;

    public RetrieveCriOauthAccessTokenHandler(
            CredentialIssuerService credentialIssuerService,
            ConfigService configService,
            IpvSessionService ipvSessionService,
            AuditService auditService) {
        this.credentialIssuerService = credentialIssuerService;
        this.configService = configService;
        this.auditService = auditService;
        this.ipvSessionService = ipvSessionService;
    }

    @ExcludeFromGeneratedCoverageReport
    public RetrieveCriOauthAccessTokenHandler() {
        this.configService = new ConfigService();
        this.credentialIssuerService =
                new CredentialIssuerService(
                        configService, new KmsEs256Signer(configService.getSigningKeyId()));
        this.auditService = new AuditService(AuditService.getDefaultSqsClient(), configService);
        this.ipvSessionService = new IpvSessionService(configService);
    }

    @Override
    @Tracing
    @Logging(clearState = true)
    public Map<String, Object> handleRequest(Map<String, String> input, Context context)
            throws JourneyError {
        LogHelper.attachComponentIdToLogs();
        IpvSessionItem ipvSessionItem = null;
        String credentialIssuerId = null;

        String ipAddress = StepFunctionHelpers.getIpAddress(input);

        try {
            String ipvSessionId = StepFunctionHelpers.getIpvSessionId(input);
            ipvSessionItem = ipvSessionService.getIpvSession(ipvSessionId);
            ClientSessionDetailsDto clientSessionDetailsDto =
                    ipvSessionItem.getClientSessionDetails();
            String userId = clientSessionDetailsDto.getUserId();

            credentialIssuerId = ipvSessionItem.getCredentialIssuerSessionDetails().getCriId();
            String authorizationCode =
                    ipvSessionItem.getCredentialIssuerSessionDetails().getAuthorizationCode();

            LogHelper.attachGovukSigninJourneyIdToLogs(
                    clientSessionDetailsDto.getGovukSigninJourneyId());

            CredentialIssuerConfig credentialIssuerConfig =
                    getCredentialIssuerConfig(credentialIssuerId);

            String apiKey = configService.getCriPrivateApiKey(credentialIssuerConfig.getId());

            BearerAccessToken accessToken =
                    credentialIssuerService.exchangeCodeForToken(
                            authorizationCode, credentialIssuerConfig, apiKey);

            AuditEventUser auditEventUser =
                    new AuditEventUser(
                            userId,
                            ipvSessionId,
                            clientSessionDetailsDto.getGovukSigninJourneyId(),
                            ipAddress);
            String componentId =
                    configService.getSsmParameter(ConfigurationVariable.AUDIENCE_FOR_CLIENTS);

            auditService.sendAuditEvent(
                    new AuditEvent(
                            AuditEventTypes.IPV_CRI_ACCESS_TOKEN_EXCHANGED,
                            componentId,
                            auditEventUser));

            setIpvSessionItemAccessToken(ipvSessionItem, accessToken);
            ipvSessionService.updateIpvSession(ipvSessionItem);

            var message =
                    new StringMapMessage()
                            .with("lambdaResult", "Successfully retrieved cri access token.")
                            .with("criId", credentialIssuerId);
            LOGGER.info(message);

            return Map.of("result", "success");
        } catch (CredentialIssuerException e) {
            if (ipvSessionItem != null) {
                setVisitedCredentials(
                        ipvSessionItem, credentialIssuerId, false, OAuth2Error.SERVER_ERROR_CODE);
                ipvSessionService.updateIpvSession(ipvSessionItem);
            }

            throw new JourneyError();
        } catch (SqsException e) {
            LOGGER.error("Failed to send audit event to SQS queue because: {}", e.getMessage());

            setVisitedCredentials(
                    ipvSessionItem, credentialIssuerId, false, OAuth2Error.SERVER_ERROR_CODE);
            ipvSessionService.updateIpvSession(ipvSessionItem);

            throw new JourneyError();
        } catch (HttpResponseExceptionWithErrorBody e) {
            ErrorResponse errorResponse = e.getErrorResponse();
            LogHelper.logOauthError(
                    "Error in credential issuer return lambda",
                    errorResponse.getCode(),
                    errorResponse.getMessage());
            throw new BadRequestError();
        }
    }

    private void setIpvSessionItemAccessToken(
            IpvSessionItem ipvSessionItem, BearerAccessToken accessToken) {
        CredentialIssuerSessionDetailsDto credentialIssuerSessionDetailsDto =
                ipvSessionItem.getCredentialIssuerSessionDetails();
        credentialIssuerSessionDetailsDto.setAccessToken(accessToken.toAuthorizationHeader());
        ipvSessionItem.setCredentialIssuerSessionDetails(credentialIssuerSessionDetailsDto);
    }

    @Tracing
    private CredentialIssuerConfig getCredentialIssuerConfig(String criId) {
        return configService.getCredentialIssuerActiveConnectionConfig(criId);
    }

    @Tracing
    private void setVisitedCredentials(
            IpvSessionItem ipvSessionItem,
            String criId,
            boolean returnedWithVc,
            String oauthError) {
        ipvSessionItem.addVisitedCredentialIssuerDetails(
                new VisitedCredentialIssuerDetailsDto(criId, returnedWithVc, oauthError));
    }
}
