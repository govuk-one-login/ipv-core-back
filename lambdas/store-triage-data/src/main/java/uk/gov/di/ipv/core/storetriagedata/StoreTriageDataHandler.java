package uk.gov.di.ipv.core.storetriagedata;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.message.StringMapMessage;
import software.amazon.lambda.powertools.logging.Logging;
import software.amazon.lambda.powertools.metrics.FlushMetrics;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.core.library.exceptions.IpvSessionNotFoundException;
import uk.gov.di.ipv.core.library.helpers.ApiGatewayResponseGenerator;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.helpers.RequestHelper;
import uk.gov.di.ipv.core.library.persistence.item.DynamicRoutingState;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.storetriagedata.domain.StoreTriageDataRequest;
import uk.gov.di.ipv.core.storetriagedata.exceptions.InvalidTriageDataException;
import uk.gov.di.ipv.core.storetriagedata.triage.TriageQuestions;

import java.util.Map;

import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_ERROR_DESCRIPTION;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_MESSAGE_DESCRIPTION;

public class StoreTriageDataHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {
    private static final Logger LOGGER = LogManager.getLogger();
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    private final ConfigService configService;
    private final IpvSessionService ipvSessionService;
    private final TriageQuestions triageQuestions;

    public StoreTriageDataHandler(
            ConfigService configService,
            IpvSessionService ipvSessionService,
            TriageQuestions triageQuestions) {
        this.configService = configService;
        this.ipvSessionService = ipvSessionService;
        this.triageQuestions = triageQuestions;
    }

    @ExcludeFromGeneratedCoverageReport
    public StoreTriageDataHandler() {
        this(ConfigService.create());
    }

    @ExcludeFromGeneratedCoverageReport
    public StoreTriageDataHandler(ConfigService configService) {
        this(configService, new IpvSessionService(configService), TriageQuestions.createDefault());
    }

    @Override
    @Logging(clearState = true)
    @FlushMetrics(captureColdStart = true)
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent input, Context context) {
        LogHelper.attachTraceId();
        LogHelper.attachComponentId(configService);

        try {
            configService.setFeatureSet(RequestHelper.getFeatureSet(input));
            var ipvSessionId = RequestHelper.getIpvSessionId(input);

            var request = parseRequest(input);
            var question =
                    triageQuestions
                            .find(request.pageId())
                            .orElseThrow(
                                    () ->
                                            new InvalidTriageDataException(
                                                    ErrorResponse.UNKNOWN_TRIAGE_PAGE,
                                                    "No triage question for page "
                                                            + request.pageId()));

            var ipvSessionItem = ipvSessionService.getIpvSession(ipvSessionId);
            if (ipvSessionItem.getDynamicRoutingState() == null) {
                ipvSessionItem.setDynamicRoutingState(new DynamicRoutingState());
            }

            question.apply(request.answers(), ipvSessionItem.getDynamicRoutingState());
            ipvSessionService.updateIpvSession(ipvSessionItem);

            LOGGER.info(
                    new StringMapMessage()
                            .with(
                                    LOG_MESSAGE_DESCRIPTION.getFieldName(),
                                    "Stored triage data for page " + request.pageId()));

            return ApiGatewayResponseGenerator.proxyJsonResponse(HTTPResponse.SC_OK, Map.of());
        } catch (HttpResponseExceptionWithErrorBody e) {
            return buildErrorResponse(e.getResponseCode(), e.getErrorResponse());
        } catch (InvalidTriageDataException e) {
            LOGGER.warn(
                    new StringMapMessage()
                            .with(LOG_MESSAGE_DESCRIPTION.getFieldName(), "Invalid triage data")
                            .with(LOG_ERROR_DESCRIPTION.getFieldName(), e.getMessage()));
            return buildErrorResponse(HTTPResponse.SC_BAD_REQUEST, e.getErrorResponse());
        } catch (IpvSessionNotFoundException e) {
            return buildErrorResponse(
                    HTTPResponse.SC_BAD_REQUEST, ErrorResponse.IPV_SESSION_NOT_FOUND);
        } catch (Exception e) {
            LOGGER.error(LogHelper.buildErrorMessage("Unhandled lambda exception", e));
            throw e;
        }
    }

    private StoreTriageDataRequest parseRequest(APIGatewayProxyRequestEvent input)
            throws InvalidTriageDataException {
        if (input.getBody() == null) {
            throw new InvalidTriageDataException(
                    ErrorResponse.INVALID_STORE_TRIAGE_DATA_REQUEST, "Missing request body");
        }
        try {
            var request = OBJECT_MAPPER.readValue(input.getBody(), StoreTriageDataRequest.class);
            if (request == null || request.pageId() == null) {
                throw new InvalidTriageDataException(
                        ErrorResponse.INVALID_STORE_TRIAGE_DATA_REQUEST, "Missing pageId");
            }
            return request;
        } catch (JsonProcessingException e) {
            throw new InvalidTriageDataException(
                    ErrorResponse.INVALID_STORE_TRIAGE_DATA_REQUEST, "Unparseable request body");
        }
    }

    private APIGatewayProxyResponseEvent buildErrorResponse(
            int statusCode, ErrorResponse errorResponse) {
        LOGGER.error(LogHelper.buildLogMessage(errorResponse.getMessage()));
        return ApiGatewayResponseGenerator.proxyJsonResponse(statusCode, errorResponse);
    }
}
