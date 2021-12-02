package uk.gov.di.ipv.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.service.AccessTokenService;
import uk.gov.di.ipv.service.UserIdentityService;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class UserIdentityHandlerTest {

    private static final String TEST_IPV_SESSION_ID = UUID.randomUUID().toString();

    @Mock
    private Context mockContext;

    @Mock
    private UserIdentityService mockUserIdentityService;

    @Mock
    private AccessTokenService mockAccessTokenService;

    private UserIdentityHandler userInfoHandler;
    private Map<String, String> userIssuedCredential;

    ObjectMapper objectMapper = new ObjectMapper();
    Map<String, String> responseBody = new HashMap<>();

    @BeforeEach
    void setUp() {
        userIssuedCredential = new HashMap<>();

        userIssuedCredential.put("id", "12345");
        userIssuedCredential.put("type", "Test credential");
        userIssuedCredential.put("foo", "bar");

        userInfoHandler = new UserIdentityHandler(mockUserIdentityService, mockAccessTokenService);
    }

    @Test
    void shouldReturn200OnSuccessfulUserIdentityRequest() {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        AccessToken accessToken = new BearerAccessToken();
        Map<String, String> headers = Collections.singletonMap("Authorization", accessToken.toAuthorizationHeader());
        event.setHeaders(headers);

        when(mockAccessTokenService.getIpvSessionIdByAccessToken(anyString())).thenReturn(TEST_IPV_SESSION_ID);
        when(mockUserIdentityService.getUserIssuedCredentials(any())).thenReturn(userIssuedCredential);

        APIGatewayProxyResponseEvent response = userInfoHandler.handleRequest(event, mockContext);

        assertEquals(200, response.getStatusCode());
    }

    @Test
    void shouldReturnCredentialsOnSuccessfulUserInfoRequest() throws JsonProcessingException {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        AccessToken accessToken = new BearerAccessToken();
        Map<String, String> headers = Collections.singletonMap("Authorization", accessToken.toAuthorizationHeader());
        event.setHeaders(headers);

        when(mockAccessTokenService.getIpvSessionIdByAccessToken(anyString())).thenReturn(TEST_IPV_SESSION_ID);
        when(mockUserIdentityService.getUserIssuedCredentials(any())).thenReturn(userIssuedCredential);

        APIGatewayProxyResponseEvent response = userInfoHandler.handleRequest(event, mockContext);
        Map<String, Object> responseBody = objectMapper.readValue(response.getBody(), Map.class);

        assertEquals(userIssuedCredential.get("id"), responseBody.get("id"));
        assertEquals(userIssuedCredential.get("type"), responseBody.get("type"));
        assertEquals(userIssuedCredential.get("foo"), responseBody.get("foo"));
    }

    @Test
    void shouldReturnErrorResponseWhenTokenIsNull() throws JsonProcessingException {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        Map<String, String> headers = Collections.singletonMap("Authorization", null);
        event.setHeaders(headers);

        APIGatewayProxyResponseEvent response = userInfoHandler.handleRequest(event, mockContext);
        responseBody = objectMapper.readValue(response.getBody(), Map.class);

        assertEquals(400, response.getStatusCode());
        assertEquals(OAuth2Error.INVALID_REQUEST.getCode(), responseBody.get("error"));
        assertEquals(OAuth2Error.INVALID_REQUEST.appendDescription(" - Authorization header is missing from token request").getDescription(), responseBody.get("error_description"));
    }

    @Test
    void shouldReturnErrorResponseWhenTokenIsInvalid() throws JsonProcessingException {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        Map<String, String> headers = Collections.singletonMap("Authorization", "11111111");
        event.setHeaders(headers);

        APIGatewayProxyResponseEvent response = userInfoHandler.handleRequest(event, mockContext);
        responseBody = objectMapper.readValue(response.getBody(), Map.class);

        assertEquals(400, response.getStatusCode());
        assertEquals(OAuth2Error.INVALID_GRANT.getCode(), responseBody.get("error"));
        assertEquals(OAuth2Error.INVALID_GRANT.appendDescription(" - Failed to parse access token").getDescription(), responseBody.get("error_description"));
    }

    @Test
    void shouldReturnErrorResponseWhenTokenIsMissing() throws JsonProcessingException {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();

        APIGatewayProxyResponseEvent response = userInfoHandler.handleRequest(event, mockContext);
        responseBody = objectMapper.readValue(response.getBody(), Map.class);

        assertEquals(400, response.getStatusCode());
        assertEquals(OAuth2Error.INVALID_REQUEST.getCode(), responseBody.get("error"));
        assertEquals(OAuth2Error.INVALID_REQUEST.appendDescription(" - Authorization header is missing from token request").getDescription(), responseBody.get("error_description"));
    }

    @Test
    void shouldReturnErrorResponseWhenInvalidAccessTokenProvided() throws JsonProcessingException {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        AccessToken accessToken = new BearerAccessToken();
        Map<String, String> headers = Collections.singletonMap("Authorization", accessToken.toAuthorizationHeader());
        event.setHeaders(headers);

        when(mockAccessTokenService.getIpvSessionIdByAccessToken(anyString())).thenReturn(null);

        APIGatewayProxyResponseEvent response = userInfoHandler.handleRequest(event, mockContext);
        Map<String, Object> responseBody = objectMapper.readValue(response.getBody(), Map.class);

        assertEquals(403, response.getStatusCode());
        assertEquals(OAuth2Error.ACCESS_DENIED.getCode(), responseBody.get("error"));
        assertEquals(OAuth2Error.ACCESS_DENIED.appendDescription(" - The supplied access token was not found in the database").getDescription(), responseBody.get("error_description"));
    }
}
