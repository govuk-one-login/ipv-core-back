package uk.gov.di.ipv.helpers;

import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.http.HttpHeaders;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.di.ipv.domain.ErrorResponse;

import java.util.Map;

public class ApiGatewayResponseGenerator {

    private static final String CONTENT_TYPE_HEADER_VALUE = "application/json";

    private static final Logger LOGGER = LoggerFactory.getLogger(ApiGatewayResponseGenerator.class);

    public static APIGatewayProxyResponseEvent proxyErrorResponse(
            int statusCode, ErrorResponse errorResponse) {
        try {
            return proxyResponse(
                    statusCode, new ObjectMapper().writeValueAsString(errorResponse));
        } catch (JsonProcessingException e) {
            LOGGER.warn("Unable to generateApiGatewayProxyErrorResponse: " + e);
            return proxyResponse(500, "Internal server error");
        }
    }

    public static APIGatewayProxyResponseEvent proxyResponse(
            int statusCode, String body) {
        APIGatewayProxyResponseEvent apiGatewayProxyResponseEvent =
                new APIGatewayProxyResponseEvent();
        Map<String, String> headers = Map.of(
                HttpHeaders.CONTENT_TYPE, CONTENT_TYPE_HEADER_VALUE
        );
        apiGatewayProxyResponseEvent.setHeaders(headers);
        apiGatewayProxyResponseEvent.setStatusCode(statusCode);
        apiGatewayProxyResponseEvent.setBody(body);

        return apiGatewayProxyResponseEvent;
    }
}
