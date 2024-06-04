package uk.gov.di.ipv.core.library.helpers;

import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.oauth2.sdk.OAuth2Error;
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

    public static APIGatewayProxyResponseEvent proxyResponse(
            int statusCode, String body, Map<String, String> headers) {
        APIGatewayProxyResponseEvent apiGatewayProxyResponseEvent =
                new APIGatewayProxyResponseEvent();
        apiGatewayProxyResponseEvent.setHeaders(headers);
        apiGatewayProxyResponseEvent.setStatusCode(statusCode);
        apiGatewayProxyResponseEvent.setBody(body);

        return apiGatewayProxyResponseEvent;
    }

    public static APIGatewayProxyResponseEvent getExpiredAccessTokenApiGatewayProxyResponseEvent(
            String expiryTime) {
        LOGGER.error(
                "User credential could not be retrieved. The supplied access token expired at: {}",
                expiryTime);
        return proxyJsonResponse(
                OAuth2Error.ACCESS_DENIED.getHTTPStatusCode(),
                OAuth2Error.ACCESS_DENIED
                        .appendDescription(" - The supplied access token has expired")
                        .toJSONObject());
    }

    public static APIGatewayProxyResponseEvent getRevokedAccessTokenApiGatewayProxyResponseEvent(
            String revokedTime) {
        LOGGER.error(
                "User credential could not be retrieved. The supplied access token has been revoked at: {}",
                revokedTime);
        return proxyJsonResponse(
                OAuth2Error.ACCESS_DENIED.getHTTPStatusCode(),
                OAuth2Error.ACCESS_DENIED
                        .appendDescription(" - The supplied access token has been revoked")
                        .toJSONObject());
    }

    public static APIGatewayProxyResponseEvent getUnknownAccessTokenApiGatewayProxyResponseEvent() {
        LOGGER.error(
                LogHelper.buildLogMessage(
                        "User credential could not be retrieved. The supplied access token was not found in the database."));
        return proxyJsonResponse(
                OAuth2Error.ACCESS_DENIED.getHTTPStatusCode(),
                OAuth2Error.ACCESS_DENIED
                        .appendDescription(
                                " - The supplied access token was not found in the database")
                        .toJSONObject());
    }

    public static APIGatewayProxyResponseEvent serverErrorJsonResponse(
            String errorHeader, Exception e) {
        LOGGER.error(LogHelper.buildErrorMessage(errorHeader, e));
        return proxyJsonResponse(
                OAuth2Error.SERVER_ERROR.getHTTPStatusCode(),
                OAuth2Error.SERVER_ERROR
                        .appendDescription(" - " + errorHeader + " " + e.getMessage())
                        .toJSONObject());
    }

    public static APIGatewayProxyResponseEvent getAccessDeniedApiGatewayProxyResponseEvent() {
        LOGGER.error(
                LogHelper.buildLogMessage(
                        "Access denied. Access was attempted from an invalid endpoint or journey."));
        return proxyJsonResponse(
                OAuth2Error.ACCESS_DENIED.getHTTPStatusCode(),
                OAuth2Error.ACCESS_DENIED
                        .appendDescription(
                                " - Access was attempted from an invalid endpoint or journey.")
                        .toJSONObject());
    }

    private static <T> String generateResponseBody(T body) throws JsonProcessingException {
        return OBJECT_MAPPER.writeValueAsString(body);
    }
}
