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
import software.amazon.lambda.powertools.tracing.Tracing;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.JourneyErrorResponse;
import uk.gov.di.ipv.core.library.domain.JourneyResponse;
import uk.gov.di.ipv.core.library.exceptions.ClientOauthSessionNotFoundException;
import uk.gov.di.ipv.core.library.exceptions.IpvSessionNotFoundException;
import uk.gov.di.ipv.core.library.helpers.ApiGatewayResponseGenerator;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.helpers.RequestHelper;
import uk.gov.di.ipv.core.library.persistence.item.CriResponseItem;
import uk.gov.di.ipv.core.library.service.ClientOAuthSessionDetailsService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.CriResponseService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.service.exception.InvalidCriResponseException;
import uk.gov.di.ipv.core.processmobileappcallback.dto.MobileAppCallbackRequest;
import uk.gov.di.ipv.core.processmobileappcallback.exception.InvalidMobileAppCallbackRequestException;

import java.util.Optional;

import static uk.gov.di.ipv.core.library.journeyuris.JourneyUris.JOURNEY_ERROR_PATH;
import static uk.gov.di.ipv.core.library.journeyuris.JourneyUris.JOURNEY_NEXT_PATH;

public class ProcessMobileAppCallbackHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {
    private static final Logger LOGGER = LogManager.getLogger();
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final JourneyResponse JOURNEY_NEXT = new JourneyResponse(JOURNEY_NEXT_PATH);
    private final ConfigService configService;
    private final IpvSessionService ipvSessionService;
    private final ClientOAuthSessionDetailsService clientOAuthSessionDetailsService;
    private final CriResponseService criResponseService;

    public ProcessMobileAppCallbackHandler(
            ConfigService configService,
            IpvSessionService ipvSessionService,
            ClientOAuthSessionDetailsService clientOAuthSessionDetailsService,
            CriResponseService criResponseService) {
        this.configService = configService;
        this.ipvSessionService = ipvSessionService;
        this.clientOAuthSessionDetailsService = clientOAuthSessionDetailsService;
        this.criResponseService = criResponseService;
    }

    @ExcludeFromGeneratedCoverageReport
    public ProcessMobileAppCallbackHandler() {
        configService = ConfigService.create();
        ipvSessionService = new IpvSessionService(configService);
        clientOAuthSessionDetailsService = new ClientOAuthSessionDetailsService(configService);
        criResponseService = new CriResponseService(configService);
    }

    @Override
    @Tracing
    @Logging(clearState = true)
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        try {
            var callbackRequest = parseCallbackRequest(input);

            var journeyResponse = getJourneyResponse(callbackRequest);

            return ApiGatewayResponseGenerator.proxyJsonResponse(HttpStatus.SC_OK, journeyResponse);
        } catch (InvalidMobileAppCallbackRequestException e) {
            return buildErrorResponse(e, HttpStatus.SC_BAD_REQUEST, e.getErrorResponse());
        } catch (IpvSessionNotFoundException e) {
            return buildErrorResponse(
                    e, HttpStatus.SC_BAD_REQUEST, ErrorResponse.IPV_SESSION_NOT_FOUND);
        } catch (ClientOauthSessionNotFoundException e) {
            return buildErrorResponse(e, HttpStatus.SC_BAD_REQUEST, e.getErrorResponse());
        } catch (InvalidCriResponseException e) {
            return buildErrorResponse(e, HttpStatus.SC_INTERNAL_SERVER_ERROR, e.getErrorResponse());
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

    private JourneyResponse getJourneyResponse(MobileAppCallbackRequest callbackRequest)
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
        var criResponse =
                criResponseService.getCriResponseItemWithState(userId, callbackRequest.getState());
        validateCriResponse(criResponse);

        return JOURNEY_NEXT;
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

    private void validateCriResponse(Optional<CriResponseItem> criResponse)
            throws InvalidMobileAppCallbackRequestException, InvalidCriResponseException {
        if (criResponse.isEmpty()) {
            throw new InvalidMobileAppCallbackRequestException(ErrorResponse.INVALID_OAUTH_STATE);
        }

        if (CriResponseService.STATUS_ERROR.equals(criResponse.get().getStatus())) {
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
