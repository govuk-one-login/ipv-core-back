package uk.gov.di.ipv.core.library.statemachine;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.http.HttpStatus;
import uk.gov.di.ipv.core.library.domain.JourneyErrorResponse;
import uk.gov.di.ipv.core.library.domain.JourneyRequest;
import uk.gov.di.ipv.core.library.domain.JourneyResponse;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.core.library.helpers.ApiGatewayResponseGenerator;
import uk.gov.di.ipv.core.library.helpers.RequestHelper;

import java.util.Map;

public abstract class BaseJourneyLambda
        implements RequestHandler<Map<String, Object>, Map<String, Object>> {
    public static final String JOURNEY_ERROR_PATH = "/journey/error";
    public static final String JOURNEY_NEXT_PATH = "/journey/next";
    public static final JourneyResponse JOURNEY_REUSE = new JourneyResponse("/journey/reuse");
    public static final JourneyResponse JOURNEY_NEXT = new JourneyResponse(JOURNEY_NEXT_PATH);
    public static final JourneyResponse JOURNEY_ERROR = new JourneyResponse(JOURNEY_ERROR_PATH);

    private static final ObjectMapper OBJECT_MAPPER =
            new ObjectMapper()
                    .configure(DeserializationFeature.FAIL_ON_IGNORED_PROPERTIES, false)
                    .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);

    private static final TypeReference<Map<String, Object>> RETURN_TYPE_REFERENCE =
            new TypeReference<>() {};

    @Override
    public Map<String, Object> handleRequest(Map<String, Object> event, Context context) {
        if (event.containsKey("ipvSessionId")) {
            var journeyRequest = OBJECT_MAPPER.convertValue(event, JourneyRequest.class);
            var journeyResponse = handleRequest(journeyRequest, context);

            return OBJECT_MAPPER.convertValue(journeyResponse, RETURN_TYPE_REFERENCE);
        }

        APIGatewayProxyResponseEvent apiGatewayResponse;
        try {
            APIGatewayProxyRequestEvent request =
                    OBJECT_MAPPER.convertValue(event, APIGatewayProxyRequestEvent.class);
            String ipvSessionId = null;
            try {
                ipvSessionId = RequestHelper.getIpvSessionId(request);
            } catch (HttpResponseExceptionWithErrorBody e) {
            }
            String ipAddress = null;
            try {
                ipAddress = RequestHelper.getIpAddress(request);
            } catch (HttpResponseExceptionWithErrorBody e) {
            }
            var clientOAuthSessionId = RequestHelper.getClientOAuthSessionId(request);
            var journeyRequest = new JourneyRequest(ipvSessionId, ipAddress, clientOAuthSessionId);

            var journeyResponse = handleRequest(journeyRequest, context);
            apiGatewayResponse =
                    ApiGatewayResponseGenerator.proxyJsonResponse(
                            HttpStatus.SC_OK, journeyResponse);
        } catch (Exception ex) {
            var journeyResponse =
                    new JourneyErrorResponse(
                            JOURNEY_ERROR_PATH, HttpStatus.SC_INTERNAL_SERVER_ERROR, null);

            apiGatewayResponse =
                    ApiGatewayResponseGenerator.proxyJsonResponse(
                            HttpStatus.SC_BAD_REQUEST, journeyResponse);
        }

        return OBJECT_MAPPER.convertValue(apiGatewayResponse, RETURN_TYPE_REFERENCE);
    }

    protected abstract JourneyResponse handleRequest(JourneyRequest request, Context context);
}
