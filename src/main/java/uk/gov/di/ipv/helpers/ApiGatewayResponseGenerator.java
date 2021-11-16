package uk.gov.di.ipv.helpers;

import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import uk.gov.di.ipv.domain.ErrorResponse;

public class ApiGatewayResponseGenerator {

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
        apiGatewayProxyResponseEvent.setStatusCode(statusCode);
        apiGatewayProxyResponseEvent.setBody(body);

        return apiGatewayProxyResponseEvent;
    }
}
