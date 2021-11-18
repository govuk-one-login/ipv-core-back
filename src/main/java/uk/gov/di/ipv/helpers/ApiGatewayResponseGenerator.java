package uk.gov.di.ipv.helpers;

import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.http.HttpHeaders;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.di.ipv.domain.ErrorResponse;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

public class ApiGatewayResponseGenerator {

    private static final String JSON_CONTENT_TYPE_VALUE = "application/json";
    private static final String FORM_URL_ENCODED_CONTENT_TYPE_VALUE = "application/x-www-form-urlencoded";

    private static final Logger LOGGER = LoggerFactory.getLogger(ApiGatewayResponseGenerator.class);

    public static APIGatewayProxyResponseEvent proxyErrorResponse(
            int statusCode, ErrorResponse errorResponse) {
        try {
            return proxyJsonResponse(
                    statusCode, new ObjectMapper().writeValueAsString(errorResponse), Collections.emptyMap());
        } catch (JsonProcessingException e) {
            LOGGER.warn("Unable to generateApiGatewayProxyErrorResponse: " + e);
            return proxyResponse(500, "Internal server error", Collections.emptyMap());
        }
    }

    public static APIGatewayProxyResponseEvent proxyJsonResponse(int statusCode, String body, Map<String, String> headers) {
        Map<String, String> responseHeaders = new HashMap<>(headers);
        responseHeaders.putIfAbsent(HttpHeaders.CONTENT_TYPE, JSON_CONTENT_TYPE_VALUE);

        return proxyResponse(statusCode, body, responseHeaders);
    }

    public static APIGatewayProxyResponseEvent proxyFormUrlEncodedResponse(int statusCode, String body, Map<String, String> headers) {
        Map<String, String> responseHeaders = new HashMap<>(headers);
        responseHeaders.putIfAbsent(HttpHeaders.CONTENT_TYPE, FORM_URL_ENCODED_CONTENT_TYPE_VALUE);

        return proxyResponse(statusCode, body, responseHeaders);
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
}
