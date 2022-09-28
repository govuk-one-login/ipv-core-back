package uk.gov.di.ipv.core.retrievecrioauthaccesstoken;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.util.StringUtils;
import org.apache.http.HttpStatus;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
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
import uk.gov.di.ipv.core.library.dto.CredentialIssuerRequestDto;
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

        CredentialIssuerRequestDto request =
                RequestHelper.convertRequest(input, CredentialIssuerRequestDto.class);

        try {
            String ipvSessionId = RequestHelper.getIpvSessionId(input);
            ipvSessionItem = ipvSessionService.getIpvSession(ipvSessionId);
            ClientSessionDetailsDto clientSessionDetailsDto =
                    ipvSessionItem.getClientSessionDetails();
            String userId = clientSessionDetailsDto.getUserId();

            LogHelper.attachGovukSigninJourneyIdToLogs(
                    clientSessionDetailsDto.getGovukSigninJourneyId());

            AuditEventUser auditEventUser =
                    new AuditEventUser(
                            userId,
                            ipvSessionId,
                            clientSessionDetailsDto.getGovukSigninJourneyId());
            String componentId =
                    configurationService.getSsmParameter(
                            ConfigurationVariable.AUDIENCE_FOR_CLIENTS);

            CredentialIssuerConfig credentialIssuerConfig = getCredentialIssuerConfig(request);

            auditService.sendAuditEvent(
                    new AuditEvent(
                            AuditEventTypes.IPV_CRI_AUTH_RESPONSE_RECEIVED,
                            componentId,
                            auditEventUser));

            validate(request);

            String apiKey =
                    configurationService.getCriPrivateApiKey(credentialIssuerConfig.getId());

            BearerAccessToken accessToken =
                    credentialIssuerService.exchangeCodeForToken(
                            request, credentialIssuerConfig, apiKey);

            setIpvSessionItemAccessToken(ipvSessionItem, accessToken);
            setVisitedCredentials(ipvSessionItem, request.getCredentialIssuerId(), true, null);

            ipvSessionService.updateIpvSession(ipvSessionItem);

            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    HttpStatus.SC_OK, JOURNEY_NEXT_RESPONSE);
        } catch (CredentialIssuerException e) {
            if (ipvSessionItem != null) {
                setVisitedCredentials(
                        ipvSessionItem,
                        request.getCredentialIssuerId(),
                        false,
                        OAuth2Error.SERVER_ERROR_CODE);
                ipvSessionService.updateIpvSession(ipvSessionItem);
            }

            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    HttpStatus.SC_OK, JOURNEY_ERROR_RESPONSE);
        } catch (SqsException e) {
            LOGGER.error("Failed to send audit event to SQS queue because: {}", e.getMessage());

            if (ipvSessionItem != null) {
                setVisitedCredentials(
                        ipvSessionItem,
                        request.getCredentialIssuerId(),
                        false,
                        OAuth2Error.SERVER_ERROR_CODE);
                ipvSessionService.updateIpvSession(ipvSessionItem);
            }

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
    private void validate(CredentialIssuerRequestDto request)
            throws HttpResponseExceptionWithErrorBody {

        if (StringUtils.isBlank(request.getAuthorizationCode())) {
            throw new HttpResponseExceptionWithErrorBody(
                    HttpStatus.SC_BAD_REQUEST, ErrorResponse.MISSING_AUTHORIZATION_CODE);
        }

        if (StringUtils.isBlank(request.getCredentialIssuerId())) {
            throw new HttpResponseExceptionWithErrorBody(
                    HttpStatus.SC_BAD_REQUEST, ErrorResponse.MISSING_CREDENTIAL_ISSUER_ID);
        }
        LogHelper.attachCriIdToLogs(request.getCredentialIssuerId());

        if (StringUtils.isBlank(request.getIpvSessionId())) {
            throw new HttpResponseExceptionWithErrorBody(
                    HttpStatus.SC_BAD_REQUEST, ErrorResponse.MISSING_IPV_SESSION_ID);
        }

        if (StringUtils.isBlank(request.getState())) {
            throw new HttpResponseExceptionWithErrorBody(
                    HttpStatus.SC_BAD_REQUEST, ErrorResponse.MISSING_OAUTH_STATE);
        }

        String persistedOauthState = getPersistedOauthState(request);
        if (!request.getState().equals(persistedOauthState)) {
            throw new HttpResponseExceptionWithErrorBody(
                    HttpStatus.SC_BAD_REQUEST, ErrorResponse.INVALID_OAUTH_STATE);
        }

        if (getCredentialIssuerConfig(request) == null) {
            throw new HttpResponseExceptionWithErrorBody(
                    HttpStatus.SC_BAD_REQUEST, ErrorResponse.INVALID_CREDENTIAL_ISSUER_ID);
        }
    }

    @Tracing
    private String getPersistedOauthState(CredentialIssuerRequestDto request) {
        return ipvSessionService
                .getIpvSession(request.getIpvSessionId())
                .getCredentialIssuerSessionDetails()
                .getState();
    }

    @Tracing
    private CredentialIssuerConfig getCredentialIssuerConfig(CredentialIssuerRequestDto request) {
        return configurationService.getCredentialIssuer(request.getCredentialIssuerId());
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
