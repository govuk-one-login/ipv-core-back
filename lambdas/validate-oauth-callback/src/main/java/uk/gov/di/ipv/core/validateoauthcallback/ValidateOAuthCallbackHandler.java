package uk.gov.di.ipv.core.validateoauthcallback;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.util.StringUtils;
import org.apache.http.HttpStatus;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.message.StringMapMessage;
import software.amazon.lambda.powertools.logging.Logging;
import software.amazon.lambda.powertools.tracing.Tracing;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.auditing.AuditEvent;
import uk.gov.di.ipv.core.library.auditing.AuditEventTypes;
import uk.gov.di.ipv.core.library.auditing.AuditEventUser;
import uk.gov.di.ipv.core.library.auditing.AuditExtensionErrorParams;
import uk.gov.di.ipv.core.library.auditing.AuditExtensions;
import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.dto.CredentialIssuerConfig;
import uk.gov.di.ipv.core.library.dto.CredentialIssuerRequestDto;
import uk.gov.di.ipv.core.library.dto.CredentialIssuerSessionDetailsDto;
import uk.gov.di.ipv.core.library.dto.VisitedCredentialIssuerDetailsDto;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.core.library.exceptions.SqsException;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.helpers.StepFunctionHelpers;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.ConfigurationService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;

import java.util.Arrays;
import java.util.List;
import java.util.Map;

public class ValidateOAuthCallbackHandler
        implements RequestHandler<CredentialIssuerRequestDto, Map<String, Object>> {

    private static final Logger LOGGER = LogManager.getLogger();
    private static final String JOURNEY = "journey";
    private static final Map<String, Object> JOURNEY_ACCESS_TOKEN =
            Map.of(JOURNEY, "/journey/cri/access-token");
    private static final Map<String, Object> JOURNEY_ACCESS_DENIED =
            Map.of(JOURNEY, "/journey/access-denied");
    private static final Map<String, Object> JOURNEY_ERROR = Map.of(JOURNEY, "/journey/error");
    private static final List<String> ALLOWED_OAUTH_ERROR_CODES =
            Arrays.asList(
                    OAuth2Error.INVALID_REQUEST_CODE,
                    OAuth2Error.UNAUTHORIZED_CLIENT_CODE,
                    OAuth2Error.ACCESS_DENIED_CODE,
                    OAuth2Error.UNSUPPORTED_RESPONSE_TYPE_CODE,
                    OAuth2Error.INVALID_SCOPE_CODE,
                    OAuth2Error.SERVER_ERROR_CODE,
                    OAuth2Error.TEMPORARILY_UNAVAILABLE_CODE);
    private static final String PYI_ATTEMPT_RECOVERY_PAGE_ID = "pyi-attempt-recovery";
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
    public Map<String, Object> handleRequest(CredentialIssuerRequestDto request, Context context) {
        LogHelper.attachComponentIdToLogs();

        IpvSessionItem ipvSessionItem = null;

        try {
            String ipvSessionId = request.getIpvSessionId();
            if (ipvSessionId == null) {
                throw new HttpResponseExceptionWithErrorBody(
                        HttpStatus.SC_BAD_REQUEST, ErrorResponse.MISSING_IPV_SESSION_ID);
            }
            LogHelper.attachIpvSessionIdToLogs(ipvSessionId);

            ipvSessionItem = ipvSessionService.getIpvSession(ipvSessionId);
            if (request.getError() != null) {
                return sendOauthErrorJourneyResponse(ipvSessionItem, request);
            }

            validate(request);

            sendAuditEvent(ipvSessionItem, null, request.getIpAddress());

            setIpvSessionCRIAuthorizationCode(
                    ipvSessionItem, new AuthorizationCode(request.getAuthorizationCode()));

            ipvSessionService.updateIpvSession(ipvSessionItem);

            var mapMessage =
                    new StringMapMessage()
                            .with("message", "Successfully validated oauth callback")
                            .with("criId", request.getCredentialIssuerId());
            LOGGER.info(mapMessage);

            return JOURNEY_ACCESS_TOKEN;
        } catch (HttpResponseExceptionWithErrorBody e) {
            ErrorResponse errorResponse = e.getErrorResponse();
            LogHelper.logOauthError(
                    "Error in validate oauth callback lambda",
                    errorResponse.getCode(),
                    errorResponse.getMessage());

            if (errorResponse == ErrorResponse.INVALID_OAUTH_STATE) {
                return StepFunctionHelpers.generatePageOutputMap(
                        "error", HttpStatus.SC_BAD_REQUEST, PYI_ATTEMPT_RECOVERY_PAGE_ID);
            }

            return StepFunctionHelpers.generateErrorOutputMap(
                    HttpStatus.SC_BAD_REQUEST, errorResponse);
        } catch (SqsException e) {
            LOGGER.error("Failed to send audit event to SQS queue because: {}", e.getMessage());

            setVisitedCredentials(
                    ipvSessionItem,
                    ipvSessionItem.getCredentialIssuerSessionDetails().getCriId(),
                    false,
                    OAuth2Error.SERVER_ERROR_CODE);
            ipvSessionService.updateIpvSession(ipvSessionItem);

            return JOURNEY_ERROR;
        }
    }

    @Tracing
    private Map<String, Object> sendOauthErrorJourneyResponse(
            IpvSessionItem ipvSessionItem, CredentialIssuerRequestDto request) throws SqsException {
        String error = request.getError();
        String errorDescription = request.getErrorDescription();

        AuditExtensionErrorParams extensions =
                new AuditExtensionErrorParams.Builder()
                        .setErrorCode(error)
                        .setErrorDescription(errorDescription)
                        .build();
        sendAuditEvent(ipvSessionItem, extensions, request.getIpAddress());

        if (!ALLOWED_OAUTH_ERROR_CODES.contains(error)) {
            LOGGER.warn("Unknown Oauth error code received");
        }

        if (ipvSessionItem.getCredentialIssuerSessionDetails() == null
                || !ipvSessionItem
                        .getCredentialIssuerSessionDetails()
                        .getCriId()
                        .equals(request.getCredentialIssuerId())) {
            var message =
                    new StringMapMessage()
                            .with("criId", request.getCredentialIssuerId())
                            .with("message", "Oauth error from unexpected CRI");
            LOGGER.warn(message);
            return StepFunctionHelpers.generatePageOutputMap(
                    "error", HttpStatus.SC_BAD_REQUEST, PYI_ATTEMPT_RECOVERY_PAGE_ID);
        }

        ipvSessionItem.addVisitedCredentialIssuerDetails(
                new VisitedCredentialIssuerDetailsDto(
                        request.getCredentialIssuerId(), false, error));
        ipvSessionService.updateIpvSession(ipvSessionItem);

        if (OAuth2Error.ACCESS_DENIED_CODE.equals(error)) {
            LOGGER.info("OAuth access_denied");
            return JOURNEY_ACCESS_DENIED;
        } else {
            LogHelper.logOauthError("OAuth error received from CRI", error, errorDescription);
            return JOURNEY_ERROR;
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
        if (persistedOauthState == null || !request.getState().equals(persistedOauthState)) {
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
        CredentialIssuerSessionDetailsDto credentialIssuerSessionDetails =
                ipvSessionService
                        .getIpvSession(request.getIpvSessionId())
                        .getCredentialIssuerSessionDetails();
        if (credentialIssuerSessionDetails != null) {
            return credentialIssuerSessionDetails.getState();
        }
        return null;
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

    @Tracing
    private void sendAuditEvent(
            IpvSessionItem ipvSessionItem, AuditExtensions extensions, String ipAddress)
            throws SqsException {
        auditService.sendAuditEvent(
                new AuditEvent(
                        AuditEventTypes.IPV_CRI_AUTH_RESPONSE_RECEIVED,
                        componentId,
                        new AuditEventUser(
                                ipvSessionItem.getClientSessionDetails().getUserId(),
                                ipvSessionItem.getIpvSessionId(),
                                ipvSessionItem.getClientSessionDetails().getGovukSigninJourneyId(),
                                ipAddress),
                        extensions));
    }
}
