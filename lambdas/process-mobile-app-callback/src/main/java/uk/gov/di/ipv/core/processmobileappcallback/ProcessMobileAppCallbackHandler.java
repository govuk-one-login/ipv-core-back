package uk.gov.di.ipv.core.processmobileappcallback;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.oauth2.sdk.util.StringUtils;
import org.apache.http.HttpStatus;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.lambda.powertools.logging.Logging;
import software.amazon.lambda.powertools.metrics.Metrics;
import software.amazon.lambda.powertools.tracing.Tracing;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.domain.Cri;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.JourneyErrorResponse;
import uk.gov.di.ipv.core.library.domain.JourneyResponse;
import uk.gov.di.ipv.core.library.exception.InvalidCriResponseException;
import uk.gov.di.ipv.core.library.exceptions.ClientOauthSessionNotFoundException;
import uk.gov.di.ipv.core.library.exceptions.IpvSessionNotFoundException;
import uk.gov.di.ipv.core.library.helpers.ApiGatewayResponseGenerator;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.helpers.RequestHelper;
import uk.gov.di.ipv.core.library.persistence.item.CriResponseItem;
import uk.gov.di.ipv.core.library.service.ClientOAuthSessionDetailsService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.CriOAuthSessionService;
import uk.gov.di.ipv.core.library.service.CriResponseService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.processmobileappcallback.dto.MobileAppCallbackRequest;
import uk.gov.di.ipv.core.processmobileappcallback.exception.InvalidMobileAppCallbackRequestException;

import java.util.Objects;

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

    public ProcessMobileAppCallbackHandler(
            ConfigService configService,
            IpvSessionService ipvSessionService,
            CriOAuthSessionService criOAuthSessionService,
            ClientOAuthSessionDetailsService clientOAuthSessionDetailsService,
            CriResponseService criResponseService) {
        this.configService = configService;
        this.ipvSessionService = ipvSessionService;
        this.criOAuthSessionService = criOAuthSessionService;
        this.clientOAuthSessionDetailsService = clientOAuthSessionDetailsService;
        this.criResponseService = criResponseService;
    }

    @ExcludeFromGeneratedCoverageReport
    public ProcessMobileAppCallbackHandler() {
        configService = ConfigService.create();
        ipvSessionService = new IpvSessionService(configService);
        criOAuthSessionService = new CriOAuthSessionService(configService);
        clientOAuthSessionDetailsService = new ClientOAuthSessionDetailsService(configService);
        criResponseService = new CriResponseService(configService);
    }

    @Override
    @Tracing
    @Logging(clearState = true)
    @Metrics(captureColdStart = true)
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        try {
            var callbackRequest = parseCallbackRequest(input);

            // Check whether we are dealing with a cross-browser callback
            var crossBrowserResponse = handleCrossBrowserCallback(callbackRequest);
            if (crossBrowserResponse != null) {
                return crossBrowserResponse;
            }

            validateCallback(callbackRequest);

            return ApiGatewayResponseGenerator.proxyJsonResponse(HttpStatus.SC_OK, JOURNEY_NEXT);
        } catch (InvalidMobileAppCallbackRequestException | ClientOauthSessionNotFoundException e) {
            return buildErrorResponse(e, HttpStatus.SC_BAD_REQUEST, e.getErrorResponse());
        } catch (IpvSessionNotFoundException e) {
            return buildErrorResponse(
                    e, HttpStatus.SC_BAD_REQUEST, ErrorResponse.IPV_SESSION_NOT_FOUND);
        } catch (InvalidCriResponseException e) {
            return buildErrorResponse(e, HttpStatus.SC_INTERNAL_SERVER_ERROR, e.getErrorResponse());
        } catch (Exception e) {
            LOGGER.error(LogHelper.buildErrorMessage("Unhandled lambda exception", e));
            throw e;
        }
    }

    private APIGatewayProxyResponseEvent handleCrossBrowserCallback(
            MobileAppCallbackRequest callbackRequest) {
        // If we don't have an IPV session, but we do have a valid CRI state value then we may be
        // dealing with a cross-browser callback. In that case we need to send the user back to
        // orchestration to login again in this browser.
        if (!StringUtils.isBlank(callbackRequest.getIpvSessionId())) {
            return null;
        }

        var criState = callbackRequest.getState();
        if (StringUtils.isBlank(criState)) {
            return null;
        }

        var criOAuthSessionItem = criOAuthSessionService.getCriOauthSessionItem(criState);
        if (criOAuthSessionItem == null) {
            return null;
        }

        var response =
                new JourneyResponse(
                        JOURNEY_BUILD_CLIENT_OAUTH_RESPONSE_PATH,
                        criOAuthSessionItem.getClientOAuthSessionId());

        return ApiGatewayResponseGenerator.proxyJsonResponse(HttpStatus.SC_OK, response);
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

    private void validateCallback(MobileAppCallbackRequest callbackRequest)
            throws InvalidMobileAppCallbackRequestException, IpvSessionNotFoundException,
                    ClientOauthSessionNotFoundException, InvalidCriResponseException {
        // Validate callback sessions
        validateSessionId(callbackRequest);

        // Get/ set session items/ config
        var ipvSessionItem = ipvSessionService.getIpvSession(callbackRequest.getIpvSessionId());
        var clientOAuthSessionItem =
                clientOAuthSessionDetailsService.getClientOAuthSession(
                        ipvSessionItem.getClientOAuthSessionId());
        var userId = clientOAuthSessionItem.getUserId();
        configService.setFeatureSet(callbackRequest.getFeatureSet());

        // Attach variables to logs
        LogHelper.attachGovukSigninJourneyIdToLogs(
                clientOAuthSessionItem.getGovukSigninJourneyId());
        LogHelper.attachIpvSessionIdToLogs(callbackRequest.getIpvSessionId());
        LogHelper.attachFeatureSetToLogs(callbackRequest.getFeatureSet());
        LogHelper.attachComponentId(configService);

        // Validate callback request
        validateCallbackRequest(callbackRequest);

        // Retrieve and validate cri response
        var criResponse = criResponseService.getCriResponseItem(userId, Cri.DCMAW_ASYNC);
        validateCriResponse(criResponse, callbackRequest.getState());
    }

    private void validateSessionId(MobileAppCallbackRequest callbackRequest)
            throws InvalidMobileAppCallbackRequestException {
        var ipvSessionId = callbackRequest.getIpvSessionId();

        if (StringUtils.isBlank(ipvSessionId)) {
            throw new InvalidMobileAppCallbackRequestException(
                    ErrorResponse.MISSING_IPV_SESSION_ID);
        }
    }

    private void validateCallbackRequest(MobileAppCallbackRequest callbackRequest)
            throws InvalidMobileAppCallbackRequestException {
        var state = callbackRequest.getState();

        if (StringUtils.isBlank(state)) {
            throw new InvalidMobileAppCallbackRequestException(ErrorResponse.MISSING_OAUTH_STATE);
        }
    }

    private void validateCriResponse(CriResponseItem criResponse, String state)
            throws InvalidMobileAppCallbackRequestException, InvalidCriResponseException {
        if (criResponse == null || !Objects.equals(criResponse.getOauthState(), state)) {
            throw new InvalidMobileAppCallbackRequestException(
                    ErrorResponse.CRI_RESPONSE_ITEM_NOT_FOUND);
        }

        if (CriResponseService.STATUS_ERROR.equals(criResponse.getStatus())) {
            throw new InvalidCriResponseException(ErrorResponse.ERROR_MOBILE_APP_RESPONSE_STATUS);
        }
    }

    private APIGatewayProxyResponseEvent buildErrorResponse(
            Exception e, int status, ErrorResponse errorResponse) {
        LOGGER.error(LogHelper.buildErrorMessage(errorResponse.getMessage(), e));
        return ApiGatewayResponseGenerator.proxyJsonResponse(
                status,
                new JourneyErrorResponse(
                        JOURNEY_ERROR_PATH, status, errorResponse, e.getMessage()));
    }
}
