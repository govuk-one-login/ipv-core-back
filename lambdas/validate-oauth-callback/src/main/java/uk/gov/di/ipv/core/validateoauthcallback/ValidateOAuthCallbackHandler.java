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
import uk.gov.di.ipv.core.library.dto.VisitedCredentialIssuerDetailsDto;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.core.library.exceptions.SqsException;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.helpers.StepFunctionHelpers;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.CriOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.ClientOAuthSessionDetailsService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.CriOAuthSessionService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.validateoauthcallback.dto.CriCallbackRequest;

import java.util.Arrays;
import java.util.List;
import java.util.Map;

import static uk.gov.di.ipv.core.library.domain.CriConstants.DRIVING_LICENCE_CRI;
import static uk.gov.di.ipv.core.library.domain.CriConstants.PASSPORT_CRI;

public class ValidateOAuthCallbackHandler
        implements RequestHandler<CriCallbackRequest, Map<String, Object>> {

    private static final Logger LOGGER = LogManager.getLogger();
    private static final String JOURNEY = "journey";
    private static final Map<String, Object> JOURNEY_ACCESS_TOKEN =
            Map.of(JOURNEY, "/journey/cri/access-token");
    private static final Map<String, Object> JOURNEY_ACCESS_DENIED =
            Map.of(JOURNEY, "/journey/access-denied");
    private static final Map<String, Object> JOURNEY_ACCESS_DENIED_MULTI =
            Map.of(JOURNEY, "/journey/access-denied-multi-doc");
    private static final Map<String, Object> JOURNEY_TEMPORARILY_UNAVAILABLE =
            Map.of(JOURNEY, "/journey/temporarily-unavailable");
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
    private static final String PYI_TIMEOUT_RECOVERABLE_PAGE_ID = "pyi-timeout-recoverable";
    private final ConfigService configService;
    private final IpvSessionService ipvSessionService;
    private final AuditService auditService;
    private final String componentId;
    private final CriOAuthSessionService criOAuthSessionService;
    private final ClientOAuthSessionDetailsService clientOAuthSessionDetailsService;

    public ValidateOAuthCallbackHandler(
            ConfigService configService,
            IpvSessionService ipvSessionService,
            AuditService auditService,
            CriOAuthSessionService criOAuthSessionService,
            ClientOAuthSessionDetailsService clientOAuthSessionDetailsService) {
        this.configService = configService;
        this.ipvSessionService = ipvSessionService;
        this.auditService = auditService;
        this.componentId = this.configService.getSsmParameter(ConfigurationVariable.COMPONENT_ID);
        this.criOAuthSessionService = criOAuthSessionService;
        this.clientOAuthSessionDetailsService = clientOAuthSessionDetailsService;
    }

    @ExcludeFromGeneratedCoverageReport
    public ValidateOAuthCallbackHandler() {
        this.configService = new ConfigService();
        this.ipvSessionService = new IpvSessionService(configService);
        this.auditService = new AuditService(AuditService.getDefaultSqsClient(), configService);
        this.componentId = this.configService.getSsmParameter(ConfigurationVariable.COMPONENT_ID);
        this.criOAuthSessionService = new CriOAuthSessionService(configService);
        this.clientOAuthSessionDetailsService = new ClientOAuthSessionDetailsService(configService);
    }

    @Override
    @Tracing
    @Logging(clearState = true)
    public Map<String, Object> handleRequest(CriCallbackRequest callbackRequest, Context context) {
        LogHelper.attachComponentIdToLogs();

        IpvSessionItem ipvSessionItem = null;
        CriOAuthSessionItem criOAuthSessionItem = null;
        ClientOAuthSessionItem clientOAuthSessionItem;

        try {
            String ipvSessionId = callbackRequest.getIpvSessionId();
            String criOAuthSessionId = callbackRequest.getState();

            if (ipvSessionId != null && !ipvSessionId.isEmpty()) {
                ipvSessionItem = ipvSessionService.getIpvSession(ipvSessionId);
            } else if (criOAuthSessionId != null && !criOAuthSessionId.isEmpty()) {
                criOAuthSessionItem =
                        criOAuthSessionService.getCriOauthSessionItem(criOAuthSessionId);
                String clientOAuthSessionId = criOAuthSessionItem.getClientOAuthSessionId();
                var mapMessage =
                        new StringMapMessage()
                                .with("message", "No ipvSession for existing CriOAuthSession")
                                .with("criId", criOAuthSessionItem.getCriId())
                                .with("clientOAuthSessionId", clientOAuthSessionId);
                LOGGER.info(mapMessage);
                Map<String, Object> pageOutput =
                        StepFunctionHelpers.generatePageOutputMap(
                                "error",
                                HttpStatus.SC_UNAUTHORIZED,
                                PYI_TIMEOUT_RECOVERABLE_PAGE_ID);
                pageOutput.put("clientOAuthSessionId", clientOAuthSessionId);
                return pageOutput;
            } else {
                throw new HttpResponseExceptionWithErrorBody(
                        HttpStatus.SC_BAD_REQUEST, ErrorResponse.MISSING_OAUTH_STATE);
            }

            LogHelper.attachIpvSessionIdToLogs(ipvSessionItem.getIpvSessionId());

            if (ipvSessionItem.getCriOAuthSessionId() != null) {
                criOAuthSessionItem =
                        criOAuthSessionService.getCriOauthSessionItem(
                                ipvSessionItem.getCriOAuthSessionId());
            }
            clientOAuthSessionItem =
                    clientOAuthSessionDetailsService.getClientOAuthSession(
                            ipvSessionItem.getClientOAuthSessionId());

            if (callbackRequest.getError() != null) {
                return sendOauthErrorJourneyResponse(
                        ipvSessionItem,
                        criOAuthSessionItem,
                        clientOAuthSessionItem,
                        callbackRequest);
            }

            validate(callbackRequest, criOAuthSessionItem);

            sendAuditEvent(
                    ipvSessionItem, clientOAuthSessionItem, null, callbackRequest.getIpAddress());

            final AuthorizationCode authorizationCode =
                    new AuthorizationCode(callbackRequest.getAuthorizationCode());

            updateCriOAuthSessionAuthorizationCode(criOAuthSessionItem, authorizationCode);

            var mapMessage =
                    new StringMapMessage()
                            .with("message", "Successfully validated oauth callback")
                            .with("criId", callbackRequest.getCredentialIssuerId());
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
                    criOAuthSessionItem.getCriId(),
                    false,
                    OAuth2Error.SERVER_ERROR_CODE);
            ipvSessionService.updateIpvSession(ipvSessionItem);

            return JOURNEY_ERROR;
        }
    }

    @Tracing
    private Map<String, Object> sendOauthErrorJourneyResponse(
            IpvSessionItem ipvSessionItem,
            CriOAuthSessionItem criOAuthSessionItem,
            ClientOAuthSessionItem clientOAuthSessionItem,
            CriCallbackRequest callbackRequest)
            throws SqsException {
        String error = callbackRequest.getError();
        String errorDescription = callbackRequest.getErrorDescription();

        AuditExtensionErrorParams extensions =
                new AuditExtensionErrorParams.Builder()
                        .setErrorCode(error)
                        .setErrorDescription(errorDescription)
                        .build();
        sendAuditEvent(
                ipvSessionItem, clientOAuthSessionItem, extensions, callbackRequest.getIpAddress());

        if (!ALLOWED_OAUTH_ERROR_CODES.contains(error)) {
            LOGGER.warn("Unknown Oauth error code received");
        }

        if (ipvSessionItem.getCriOAuthSessionId() == null
                || criOAuthSessionItem == null
                || !criOAuthSessionItem
                        .getCriId()
                        .equals(callbackRequest.getCredentialIssuerId())) {
            var message =
                    new StringMapMessage()
                            .with("criId", callbackRequest.getCredentialIssuerId())
                            .with("message", "Oauth error from unexpected CRI");
            LOGGER.warn(message);
            return StepFunctionHelpers.generatePageOutputMap(
                    "error", HttpStatus.SC_BAD_REQUEST, PYI_ATTEMPT_RECOVERY_PAGE_ID);
        }

        ipvSessionItem.addVisitedCredentialIssuerDetails(
                new VisitedCredentialIssuerDetailsDto(
                        callbackRequest.getCredentialIssuerId(), false, error));
        ipvSessionService.updateIpvSession(ipvSessionItem);

        LogHelper.logOauthError("OAuth error received from CRI", error, errorDescription);

        if (OAuth2Error.ACCESS_DENIED_CODE.equals(error)) {
            if (configService.isEnabled(PASSPORT_CRI)
                    && configService.isEnabled(DRIVING_LICENCE_CRI)) {
                return JOURNEY_ACCESS_DENIED_MULTI;
            }
            return JOURNEY_ACCESS_DENIED;
        } else if (OAuth2Error.TEMPORARILY_UNAVAILABLE_CODE.equals(error)) {
            return JOURNEY_TEMPORARILY_UNAVAILABLE;
        } else {
            return JOURNEY_ERROR;
        }
    }

    @Tracing
    private void validate(
            CriCallbackRequest callbackRequest, CriOAuthSessionItem criOAuthSessionItem)
            throws HttpResponseExceptionWithErrorBody {

        if (StringUtils.isBlank(callbackRequest.getAuthorizationCode())) {
            throw new HttpResponseExceptionWithErrorBody(
                    HttpStatus.SC_BAD_REQUEST, ErrorResponse.MISSING_AUTHORIZATION_CODE);
        }

        if (StringUtils.isBlank(callbackRequest.getCredentialIssuerId())) {
            throw new HttpResponseExceptionWithErrorBody(
                    HttpStatus.SC_BAD_REQUEST, ErrorResponse.MISSING_CREDENTIAL_ISSUER_ID);
        }
        LogHelper.attachCriIdToLogs(callbackRequest.getCredentialIssuerId());

        if (StringUtils.isBlank(callbackRequest.getIpvSessionId())) {
            throw new HttpResponseExceptionWithErrorBody(
                    HttpStatus.SC_BAD_REQUEST, ErrorResponse.MISSING_IPV_SESSION_ID);
        }

        if (StringUtils.isBlank(callbackRequest.getState())) {
            throw new HttpResponseExceptionWithErrorBody(
                    HttpStatus.SC_BAD_REQUEST, ErrorResponse.MISSING_OAUTH_STATE);
        }

        String persistedOauthState = getPersistedOauthState(criOAuthSessionItem);
        if (!callbackRequest.getState().equals(persistedOauthState)) {
            throw new HttpResponseExceptionWithErrorBody(
                    HttpStatus.SC_BAD_REQUEST, ErrorResponse.INVALID_OAUTH_STATE);
        }

        if (getCredentialIssuerConfig(callbackRequest) == null) {
            throw new HttpResponseExceptionWithErrorBody(
                    HttpStatus.SC_BAD_REQUEST, ErrorResponse.INVALID_CREDENTIAL_ISSUER_ID);
        }
    }

    @Tracing
    private void updateCriOAuthSessionAuthorizationCode(
            CriOAuthSessionItem criOAuthSessionItem, AuthorizationCode authorizationCode) {
        if (criOAuthSessionItem != null) {
            criOAuthSessionItem.setAuthorizationCode(authorizationCode.getValue());
            criOAuthSessionService.updateCriOAuthSessionItem(criOAuthSessionItem);
        }
    }

    @Tracing
    private String getPersistedOauthState(CriOAuthSessionItem criOAuthSessionItem) {
        if (criOAuthSessionItem != null) {
            return criOAuthSessionItem.getCriOAuthSessionId();
        }
        return null;
    }

    @Tracing
    private CredentialIssuerConfig getCredentialIssuerConfig(CriCallbackRequest callbackRequest) {
        return configService.getCredentialIssuerActiveConnectionConfig(
                callbackRequest.getCredentialIssuerId());
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
            IpvSessionItem ipvSessionItem,
            ClientOAuthSessionItem clientOAuthSessionItem,
            AuditExtensions extensions,
            String ipAddress)
            throws SqsException {
        auditService.sendAuditEvent(
                new AuditEvent(
                        AuditEventTypes.IPV_CRI_AUTH_RESPONSE_RECEIVED,
                        componentId,
                        new AuditEventUser(
                                clientOAuthSessionItem.getUserId(),
                                ipvSessionItem.getIpvSessionId(),
                                clientOAuthSessionItem.getGovukSigninJourneyId(),
                                ipAddress),
                        extensions));
    }
}
