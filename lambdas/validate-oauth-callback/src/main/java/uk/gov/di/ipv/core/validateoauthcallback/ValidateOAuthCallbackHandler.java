package uk.gov.di.ipv.core.validateoauthcallback;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.OAuth2Error;
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
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.JourneyResponse;
import uk.gov.di.ipv.core.library.dto.CredentialIssuerConfig;
import uk.gov.di.ipv.core.library.dto.CredentialIssuerRequestDto;
import uk.gov.di.ipv.core.library.dto.CredentialIssuerSessionDetailsDto;
import uk.gov.di.ipv.core.library.dto.VisitedCredentialIssuerDetailsDto;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.core.library.exceptions.SqsException;
import uk.gov.di.ipv.core.library.helpers.ApiGatewayResponseGenerator;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.helpers.RequestHelper;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.ConfigurationService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;

public class ValidateOAuthCallbackHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {

    private static final Logger LOGGER = LogManager.getLogger();
    private static final JourneyResponse JOURNEY_NEXT_RESPONSE =
            new JourneyResponse("/journey/next");
    private static final JourneyResponse JOURNEY_ERROR_RESPONSE =
            new JourneyResponse("/journey/error");
    private final ConfigurationService configurationService;
    private final IpvSessionService ipvSessionService;
    private final AuditService auditService;
    private final String componentId;

    public ValidateOAuthCallbackHandler(
            ConfigurationService configurationService,
            IpvSessionService ipvSessionService,
            AuditService auditService) {
        this.configurationService = configurationService;
        this.ipvSessionService = ipvSessionService;
        this.auditService = auditService;
        this.componentId =
                this.configurationService.getSsmParameter(
                        ConfigurationVariable.AUDIENCE_FOR_CLIENTS);
    }

    @ExcludeFromGeneratedCoverageReport
    public ValidateOAuthCallbackHandler() {
        this.configurationService = new ConfigurationService();
        this.ipvSessionService = new IpvSessionService(configurationService);
        this.auditService =
                new AuditService(AuditService.getDefaultSqsClient(), configurationService);
        this.componentId =
                this.configurationService.getSsmParameter(
                        ConfigurationVariable.AUDIENCE_FOR_CLIENTS);
    }

    @Override
    @Tracing
    @Logging(clearState = true)
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        LogHelper.attachComponentIdToLogs();

        IpvSessionItem ipvSessionItem = null;

        try {
            CredentialIssuerRequestDto request =
                    RequestHelper.convertRequest(input, CredentialIssuerRequestDto.class);

            validate(request);

            String ipvSessionId = RequestHelper.getIpvSessionId(input);
            ipvSessionItem = ipvSessionService.getIpvSession(ipvSessionId);

            auditService.sendAuditEvent(
                    new AuditEvent(
                            AuditEventTypes.IPV_CRI_AUTH_RESPONSE_RECEIVED,
                            componentId,
                            new AuditEventUser(
                                    ipvSessionItem.getClientSessionDetails().getUserId(),
                                    ipvSessionItem.getIpvSessionId(),
                                    ipvSessionItem
                                            .getClientSessionDetails()
                                            .getGovukSigninJourneyId())));

            setIpvSessionCRIAuthorizationCode(
                    ipvSessionItem, new AuthorizationCode(request.getAuthorizationCode()));

            ipvSessionService.updateIpvSession(ipvSessionItem);

            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    HttpStatus.SC_OK, JOURNEY_NEXT_RESPONSE);
        } catch (HttpResponseExceptionWithErrorBody e) {
            ErrorResponse errorResponse = e.getErrorResponse();

            LogHelper.logOauthError(
                    "Error in validate oauth callback lambda",
                    errorResponse.getCode(),
                    errorResponse.getMessage());

            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    HttpStatus.SC_BAD_REQUEST, e.getErrorBody());
        } catch (SqsException e) {
            LOGGER.error("Failed to send audit event to SQS queue because: {}", e.getMessage());

            setVisitedCredentials(
                    ipvSessionItem,
                    ipvSessionItem.getCredentialIssuerSessionDetails().getCriId(),
                    false,
                    OAuth2Error.SERVER_ERROR_CODE);
            ipvSessionService.updateIpvSession(ipvSessionItem);

            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    HttpStatus.SC_OK, JOURNEY_ERROR_RESPONSE);
        }
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
    private void setIpvSessionCRIAuthorizationCode(
            IpvSessionItem ipvSessionItem, AuthorizationCode authorizationCode) {
        CredentialIssuerSessionDetailsDto credentialIssuerSessionDetailsDto =
                ipvSessionItem.getCredentialIssuerSessionDetails();
        credentialIssuerSessionDetailsDto.setAuthorizationCode(authorizationCode.getValue());
        ipvSessionItem.setCredentialIssuerSessionDetails(credentialIssuerSessionDetailsDto);
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
