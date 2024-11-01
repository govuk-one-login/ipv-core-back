package uk.gov.di.ipv.core.library.helpers;

import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.util.Collections;
import java.util.Map;

import static com.nimbusds.common.contenttype.ContentType.APPLICATION_JSON;
import static software.amazon.awssdk.http.Header.CONTENT_TYPE;

public class ApiGatewayResponseGenerator {
    private static final Logger LOGGER = LogManager.getLogger();

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    private ApiGatewayResponseGenerator() {}

    public static <T> APIGatewayProxyResponseEvent proxyJsonResponse(int statusCode, T body) {

        Map<String, String> responseHeaders = Map.of(CONTENT_TYPE, APPLICATION_JSON.getType());

        try {
            return proxyResponse(statusCode, generateResponseBody(body), responseHeaders);
        } catch (JsonProcessingException e) {
            LOGGER.error(
                    LogHelper.buildErrorMessage(
                            "Unable to generateApiGatewayProxyErrorResponse", e));
            return proxyResponse(500, "Internal server error", Collections.emptyMap());
        }
    }

    public static APIGatewayProxyResponseEvent proxyResponse(int statusCode) {
        APIGatewayProxyResponseEvent apiGatewayProxyResponseEvent =
                new APIGatewayProxyResponseEvent();
        apiGatewayProxyResponseEvent.setStatusCode(statusCode);

        return apiGatewayProxyResponseEvent;
    }

    public static APIGatewayProxyResponseEvent proxyResponse(
            int statusCode, String body, Map<String, String> headers) {
        APIGatewayProxyResponseEvent apiGatewayProxyResponseEvent =
                new APIGatewayProxyResponseEvent();
        apiGatewayProxyResponseEvent.setHeaders(headers);
        apiGatewayProxyResponseEvent.setStatusCode(statusCode);
        apiGatewayProxyResponseEvent.setBody(body);

        return apiGatewayProxyResponseEvent;
    }

    private static <T> String generateResponseBody(T body) throws JsonProcessingException {
        return OBJECT_MAPPER.writeValueAsString(body);
    }
}
