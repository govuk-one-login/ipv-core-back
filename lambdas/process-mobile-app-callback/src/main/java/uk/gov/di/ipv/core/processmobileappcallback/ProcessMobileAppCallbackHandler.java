package uk.gov.di.ipv.core.processmobileappcallback;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.oauth2.sdk.util.StringUtils;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.awssdk.http.HttpStatusCode;
import software.amazon.lambda.powertools.logging.Logging;
import software.amazon.lambda.powertools.metrics.FlushMetrics;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.auditing.AuditEvent;
import uk.gov.di.ipv.core.library.auditing.AuditEventTypes;
import uk.gov.di.ipv.core.library.auditing.AuditEventUser;
import uk.gov.di.ipv.core.library.auditing.restricted.AuditRestrictedDeviceInformation;
import uk.gov.di.ipv.core.library.criresponse.exception.InvalidCriResponseException;
import uk.gov.di.ipv.core.library.criresponse.service.CriResponseService;
import uk.gov.di.ipv.core.library.domain.Cri;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.JourneyErrorResponse;
import uk.gov.di.ipv.core.library.domain.JourneyResponse;
import uk.gov.di.ipv.core.library.exceptions.ClientOauthSessionNotFoundException;
import uk.gov.di.ipv.core.library.exceptions.IpvSessionNotFoundException;
import uk.gov.di.ipv.core.library.helpers.ApiGatewayResponseGenerator;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.helpers.RequestHelper;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.ClientOAuthSessionDetailsService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.CriOAuthSessionService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.processmobileappcallback.dto.MobileAppCallbackRequest;
import uk.gov.di.ipv.core.processmobileappcallback.exception.InvalidMobileAppCallbackRequestException;

import java.util.Objects;
import java.util.Set;

import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_BUILD_CLIENT_OAUTH_RESPONSE_PATH;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_ERROR_PATH;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_NEXT_PATH;

public class ProcessMobileAppCallbackHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {
    private static final Logger LOGGER = LogManager.getLogger();
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final JourneyResponse JOURNEY_NEXT = new JourneyResponse(JOURNEY_NEXT_PATH);
    private final ConfigService configService;
    private final IpvSessionService ipvSessionService;
    private final CriOAuthSessionService criOAuthSessionService;
    private final ClientOAuthSessionDetailsService clientOAuthSessionDetailsService;
    private final CriResponseService criResponseService;
    private final AuditService auditService;

    public ProcessMobileAppCallbackHandler(
            ConfigService configService,
            IpvSessionService ipvSessionService,
            CriOAuthSessionService criOAuthSessionService,
            ClientOAuthSessionDetailsService clientOAuthSessionDetailsService,
            CriResponseService criResponseService,
            AuditService auditService) {
        this.configService = configService;
        this.ipvSessionService = ipvSessionService;
        this.criOAuthSessionService = criOAuthSessionService;
        this.clientOAuthSessionDetailsService = clientOAuthSessionDetailsService;
        this.criResponseService = criResponseService;
        this.auditService = auditService;
    }

    @ExcludeFromGeneratedCoverageReport
    public ProcessMobileAppCallbackHandler() {
        configService = ConfigService.create();
        ipvSessionService = new IpvSessionService(configService);
        criOAuthSessionService = new CriOAuthSessionService(configService);
        clientOAuthSessionDetailsService = new ClientOAuthSessionDetailsService(configService);
        criResponseService = new CriResponseService(configService);
        auditService = AuditService.create(configService);
    }

    @Override
    @Logging(clearState = true)
    @FlushMetrics(captureColdStart = true)
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        LogHelper.attachTraceId();
        LogHelper.attachComponentId(configService);

        try {
            var callbackRequest = parseCallbackRequest(input);

            var response = validateCallback(callbackRequest);

            return ApiGatewayResponseGenerator.proxyJsonResponse(
                    HttpStatusCode.OK, Objects.requireNonNullElse(response, JOURNEY_NEXT));
        } catch (InvalidMobileAppCallbackRequestException e) {
            if (Set.of(
                            ErrorResponse.INVALID_OAUTH_STATE,
                            ErrorResponse.MISSING_IPV_SESSION_ID,
                            ErrorResponse.CRI_RESPONSE_ITEM_NOT_FOUND)
                    .contains(e.getErrorResponse())) {
                return buildErrorResponse(
                        e, HttpStatusCode.BAD_REQUEST, e.getErrorResponse(), Level.WARN);
            }
            return buildErrorResponse(
                    e, HttpStatusCode.BAD_REQUEST, e.getErrorResponse(), Level.ERROR);
        } catch (ClientOauthSessionNotFoundException e) {
            return buildErrorResponse(
                    e, HttpStatusCode.BAD_REQUEST, e.getErrorResponse(), Level.ERROR);
        } catch (IpvSessionNotFoundException e) {
            return buildErrorResponse(
                    e,
                    HttpStatusCode.BAD_REQUEST,
                    ErrorResponse.IPV_SESSION_NOT_FOUND,
                    Level.ERROR);
        } catch (InvalidCriResponseException e) {
            return buildErrorResponse(
                    e, HttpStatusCode.INTERNAL_SERVER_ERROR, e.getErrorResponse(), Level.ERROR);
        } catch (Exception e) {
            LOGGER.error(LogHelper.buildErrorMessage("Unhandled lambda exception", e));
            throw e;
        } finally {
            auditService.awaitAuditEvents();
        }
    }

    private MobileAppCallbackRequest parseCallbackRequest(APIGatewayProxyRequestEvent input)
            throws InvalidMobileAppCallbackRequestException {
        try {
            var callbackRequest =
                    OBJECT_MAPPER.readValue(input.getBody(), MobileAppCallbackRequest.class);
            callbackRequest.setIpvSessionId(input.getHeaders().get("ipv-session-id"));
            callbackRequest.setFeatureSet(RequestHelper.getFeatureSet(input.getHeaders()));
            callbackRequest.setIpAddress(input.getHeaders().get("ip-address"));
            callbackRequest.setDeviceInformation(input.getHeaders().get("txma-audit-encoded"));
            return callbackRequest;
        } catch (JsonProcessingException e) {
            throw new InvalidMobileAppCallbackRequestException(
                    ErrorResponse.FAILED_TO_PARSE_MOBILE_APP_CALLBACK_REQUEST_BODY);
        }
    }

    private JourneyResponse validateCallback(MobileAppCallbackRequest callbackRequest)
            throws InvalidMobileAppCallbackRequestException,
                    IpvSessionNotFoundException,
                    ClientOauthSessionNotFoundException,
                    InvalidCriResponseException {
        // Attach variables to logs
        LogHelper.attachIpvSessionIdToLogs(callbackRequest.getIpvSessionId());
        LogHelper.attachFeatureSetToLogs(callbackRequest.getFeatureSet());

        // Validate CRI state
        var criState = callbackRequest.getState();
        if (StringUtils.isBlank(criState)) {
            throw new InvalidMobileAppCallbackRequestException(ErrorResponse.MISSING_OAUTH_STATE);
        }

        var criOAuthSessionItem = criOAuthSessionService.getCriOauthSessionItem(criState);
        if (criOAuthSessionItem == null) {
            throw new InvalidMobileAppCallbackRequestException(ErrorResponse.INVALID_OAUTH_STATE);
        }

        // Fetch client session
        var clientOAuthSessionId = criOAuthSessionItem.getClientOAuthSessionId();
        var clientOAuthSessionItem =
                clientOAuthSessionDetailsService.getClientOAuthSession(clientOAuthSessionId);
        var userId = clientOAuthSessionItem.getUserId();
        var govukSigninJourneyId = clientOAuthSessionItem.getGovukSigninJourneyId();

        // Attach variables to logs
        LogHelper.attachGovukSigninJourneyIdToLogs(govukSigninJourneyId);

        // Check IPV session
        var ipvSessionId = callbackRequest.getIpvSessionId();
        if (StringUtils.isBlank(ipvSessionId)) {
            LOGGER.info(
                    LogHelper.buildLogMessage("Missing IPV session id - Cross-browser scenario."));

            String previousIpvSessionId = null;
            try {
                previousIpvSessionId =
                        ipvSessionService
                                .getIpvSessionByClientOAuthSessionId(clientOAuthSessionId)
                                .getIpvSessionId();
            } catch (IpvSessionNotFoundException e) {
                LOGGER.warn(
                        LogHelper.buildLogMessage(
                                String.format(
                                        "Previous IPV session not found for client OAuth session ID: %s",
                                        clientOAuthSessionId)));
            }

            auditService.sendAuditEvent(
                    AuditEvent.createWithDeviceInformation(
                            AuditEventTypes.IPV_APP_MISSING_CONTEXT,
                            configService.getComponentId(),
                            new AuditEventUser(
                                    userId,
                                    previousIpvSessionId,
                                    govukSigninJourneyId,
                                    callbackRequest.getIpAddress()),
                            new AuditRestrictedDeviceInformation(
                                    callbackRequest.getDeviceInformation())));

            return new JourneyResponse(
                    JOURNEY_BUILD_CLIENT_OAUTH_RESPONSE_PATH, clientOAuthSessionId);
        }

        // Validate cri response item
        var criResponse = criResponseService.getCriResponseItem(userId, Cri.DCMAW_ASYNC);
        if (criResponse == null || !Objects.equals(criResponse.getOauthState(), criState)) {
            throw new InvalidMobileAppCallbackRequestException(
                    ErrorResponse.CRI_RESPONSE_ITEM_NOT_FOUND);
        }

        if (CriResponseService.STATUS_ERROR.equals(criResponse.getStatus())) {
            throw new InvalidCriResponseException(ErrorResponse.ERROR_MOBILE_APP_RESPONSE_STATUS);
        }

        return null;
    }

    private APIGatewayProxyResponseEvent buildErrorResponse(
            Exception e, int status, ErrorResponse errorResponse, Level level) {
        LOGGER.log(level, LogHelper.buildErrorMessage(errorResponse.getMessage(), e));
        return ApiGatewayResponseGenerator.proxyJsonResponse(
                status,
                new JourneyErrorResponse(
                        JOURNEY_ERROR_PATH, status, errorResponse, e.getMessage()));
    }
}
