package uk.gov.di.ipv.core.retrievecrioauthaccesstoken;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import org.apache.http.HttpStatus;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.message.MapMessage;
import software.amazon.lambda.powertools.logging.Logging;
import software.amazon.lambda.powertools.tracing.Tracing;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.auditing.AuditEvent;
import uk.gov.di.ipv.core.library.auditing.AuditEventTypes;
import uk.gov.di.ipv.core.library.auditing.AuditEventUser;
import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
import uk.gov.di.ipv.core.library.domain.CredentialIssuerException;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.JourneyResponse;
import uk.gov.di.ipv.core.library.dto.ClientSessionDetailsDto;
import uk.gov.di.ipv.core.library.dto.CredentialIssuerConfig;
import uk.gov.di.ipv.core.library.dto.CredentialIssuerSessionDetailsDto;
import uk.gov.di.ipv.core.library.dto.VisitedCredentialIssuerDetailsDto;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.core.library.exceptions.SqsException;
import uk.gov.di.ipv.core.library.helpers.ApiGatewayResponseGenerator;
import uk.gov.di.ipv.core.library.helpers.KmsEs256Signer;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.helpers.RequestHelper;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.ConfigurationService;
import uk.gov.di.ipv.core.library.service.CredentialIssuerService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;

public class RetrieveCriOauthAccessTokenHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {
    private static final Logger LOGGER = LogManager.getLogger();
    private static final JourneyResponse JOURNEY_NEXT_RESPONSE =
            new JourneyResponse("/journey/next");
    private static final JourneyResponse JOURNEY_ERROR_RESPONSE =
            new JourneyResponse("/journey/error");
    private final CredentialIssuerService credentialIssuerService;
    private final ConfigurationService configurationService;
    private final AuditService auditService;
    private final IpvSessionService ipvSessionService;

    public RetrieveCriOauthAccessTokenHandler(
            CredentialIssuerService credentialIssuerService,
            ConfigurationService configurationService,
            IpvSessionService ipvSessionService,
            AuditService auditService) {
        this.credentialIssuerService = credentialIssuerService;
        this.configurationService = configurationService;
        this.auditService = auditService;
        this.ipvSessionService = ipvSessionService;
    }

    @ExcludeFromGeneratedCoverageReport
    public RetrieveCriOauthAccessTokenHandler() {
        this.configurationService = new ConfigurationService();
        this.credentialIssuerService =
                new CredentialIssuerService(
                        configurationService,
                        new KmsEs256Signer(configurationService.getSigningKeyId()));
        this.auditService =
                new AuditService(AuditService.getDefaultSqsClient(), configurationService);
        this.ipvSessionService = new IpvSessionService(configurationService);
    }

    @Override
    @Tracing
    @Logging(clearState = true)
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        LogHelper.attachComponentIdToLogs();
        IpvSessionItem ipvSessionItem = null;
        String credentialIssuerId = null;

        try {
            String ipvSessionId = RequestHelper.getIpvSessionId(input);
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

            String apiKey =
                    configurationService.getCriPrivateApiKey(credentialIssuerConfig.getId());

            BearerAccessToken accessToken =
                    credentialIssuerService.exchangeCodeForToken(
                            authorizationCode, credentialIssuerConfig, apiKey);

            AuditEventUser auditEventUser =
                    new AuditEventUser(
                            userId,
                            ipvSessionId,
                            clientSessionDetailsDto.getGovukSigninJourneyId());
            String componentId =
                    configurationService.getSsmParameter(
                            ConfigurationVariable.AUDIENCE_FOR_CLIENTS);

            auditService.sendAuditEvent(
                    new AuditEvent(
                            AuditEventTypes.IPV_CRI_ACCESS_TOKEN_EXCHANGED,
                            componentId,
                            auditEventUser));

            setIpvSessionItemAccessToken(ipvSessionItem, accessToken);
            setVisitedCredentials(ipvSessionItem, credentialIssuerId, true, null);
            ipvSessionService.updateIpvSession(ipvSessionItem);

            var message =
                    new MapMessage()
                            .with("lambdaResult", "Successfully retrieved cri access token.")
                            .with("criId", credentialIssuerId);
            LOGGER.info(message);

            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    HttpStatus.SC_OK, JOURNEY_NEXT_RESPONSE);
        } catch (CredentialIssuerException e) {
            if (ipvSessionItem != null) {
                setVisitedCredentials(
                        ipvSessionItem, credentialIssuerId, false, OAuth2Error.SERVER_ERROR_CODE);
                ipvSessionService.updateIpvSession(ipvSessionItem);
            }

            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    HttpStatus.SC_OK, JOURNEY_ERROR_RESPONSE);
        } catch (SqsException e) {
            LOGGER.error("Failed to send audit event to SQS queue because: {}", e.getMessage());

            setVisitedCredentials(
                    ipvSessionItem, credentialIssuerId, false, OAuth2Error.SERVER_ERROR_CODE);
            ipvSessionService.updateIpvSession(ipvSessionItem);

            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    HttpStatus.SC_OK, JOURNEY_ERROR_RESPONSE);
        } catch (HttpResponseExceptionWithErrorBody e) {
            ErrorResponse errorResponse = e.getErrorResponse();
            LogHelper.logOauthError(
                    "Error in credential issuer return lambda",
                    errorResponse.getCode(),
                    errorResponse.getMessage());
            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    HttpStatus.SC_BAD_REQUEST, e.getErrorBody());
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
        return configurationService.getCredentialIssuer(criId);
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
