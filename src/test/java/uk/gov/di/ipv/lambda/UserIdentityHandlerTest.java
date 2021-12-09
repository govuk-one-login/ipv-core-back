package uk.gov.di.ipv.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.BearerTokenError;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.service.AccessTokenService;
import uk.gov.di.ipv.service.UserIdentityService;
import uk.org.webcompere.systemstubs.environment.EnvironmentVariables;
import uk.org.webcompere.systemstubs.jupiter.SystemStub;
import uk.org.webcompere.systemstubs.jupiter.SystemStubsExtension;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.service.ConfigurationService.IS_LOCAL;

@ExtendWith(MockitoExtension.class)
@ExtendWith(SystemStubsExtension.class)
class UserIdentityHandlerTest {

    @SystemStub private EnvironmentVariables environmentVariables;

    private static final String TEST_IPV_SESSION_ID = UUID.randomUUID().toString();

    @Mock private Context mockContext;

    @Mock private UserIdentityService mockUserIdentityService;

    @Mock private AccessTokenService mockAccessTokenService;

    private final ObjectMapper objectMapper = new ObjectMapper();

    private UserIdentityHandler userInfoHandler;
    private Map<String, String> userIssuedCredential;
    private Map<String, String> responseBody;

    @BeforeEach
    void setUp() {
        userIssuedCredential = new HashMap<>();
        responseBody = new HashMap<>();

        userIssuedCredential.put("id", "12345");
        userIssuedCredential.put("type", "Test credential");
        userIssuedCredential.put("foo", "bar");

        userInfoHandler = new UserIdentityHandler(mockUserIdentityService, mockAccessTokenService);
    }

    @Test
    void noArgsConstructor() {
        environmentVariables.set(IS_LOCAL, "true");
        assertDoesNotThrow(() -> new UserIdentityHandler());
    }

    @Test
    void shouldReturn200OnSuccessfulUserIdentityRequest() {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        AccessToken accessToken = new BearerAccessToken();
        Map<String, String> headers =
                Collections.singletonMap("Authorization", accessToken.toAuthorizationHeader());
        event.setHeaders(headers);

        when(mockAccessTokenService.getIpvSessionIdByAccessToken(anyString()))
                .thenReturn(TEST_IPV_SESSION_ID);
        when(mockUserIdentityService.getUserIssuedCredentials(any()))
                .thenReturn(userIssuedCredential);

        APIGatewayProxyResponseEvent response = userInfoHandler.handleRequest(event, mockContext);

        assertEquals(200, response.getStatusCode());
    }

    @Test
    void shouldReturnCredentialsOnSuccessfulUserInfoRequest() throws JsonProcessingException {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        AccessToken accessToken = new BearerAccessToken();
        Map<String, String> headers =
                Collections.singletonMap("Authorization", accessToken.toAuthorizationHeader());
        event.setHeaders(headers);

        when(mockAccessTokenService.getIpvSessionIdByAccessToken(anyString()))
                .thenReturn(TEST_IPV_SESSION_ID);
        when(mockUserIdentityService.getUserIssuedCredentials(any()))
                .thenReturn(userIssuedCredential);

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

        assertEquals(BearerTokenError.MISSING_TOKEN.getHTTPStatusCode(), response.getStatusCode());
        assertEquals(BearerTokenError.MISSING_TOKEN.getCode(), responseBody.get("error"));
        assertEquals(
                BearerTokenError.MISSING_TOKEN.getDescription(),
                responseBody.get("error_description"));
    }

    @Test
    void shouldReturnErrorResponseWhenTokenIsMissingBearerPrefix() throws JsonProcessingException {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        Map<String, String> headers = Collections.singletonMap("Authorization", "11111111");
        event.setHeaders(headers);

        APIGatewayProxyResponseEvent response = userInfoHandler.handleRequest(event, mockContext);
        responseBody = objectMapper.readValue(response.getBody(), Map.class);

        assertEquals(
                BearerTokenError.INVALID_REQUEST.getHTTPStatusCode(), response.getStatusCode());
        assertEquals(BearerTokenError.INVALID_REQUEST.getCode(), responseBody.get("error"));
        assertEquals(
                BearerTokenError.INVALID_REQUEST.getDescription(),
                responseBody.get("error_description"));
    }

    @Test
    void shouldReturnErrorResponseWhenTokenIsMissing() throws JsonProcessingException {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();

        APIGatewayProxyResponseEvent response = userInfoHandler.handleRequest(event, mockContext);
        responseBody = objectMapper.readValue(response.getBody(), Map.class);

        assertEquals(BearerTokenError.MISSING_TOKEN.getHTTPStatusCode(), response.getStatusCode());
        assertEquals(BearerTokenError.MISSING_TOKEN.getCode(), responseBody.get("error"));
        assertEquals(
                BearerTokenError.MISSING_TOKEN.getDescription(),
                responseBody.get("error_description"));
    }

    @Test
    void shouldReturnErrorResponseWhenInvalidAccessTokenProvided() throws JsonProcessingException {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        AccessToken accessToken = new BearerAccessToken();
        Map<String, String> headers =
                Collections.singletonMap("Authorization", accessToken.toAuthorizationHeader());
        event.setHeaders(headers);

        when(mockAccessTokenService.getIpvSessionIdByAccessToken(anyString())).thenReturn(null);

        APIGatewayProxyResponseEvent response = userInfoHandler.handleRequest(event, mockContext);
        Map<String, Object> responseBody = objectMapper.readValue(response.getBody(), Map.class);

        assertEquals(403, response.getStatusCode());
        assertEquals(OAuth2Error.ACCESS_DENIED.getCode(), responseBody.get("error"));
        assertEquals(
                OAuth2Error.ACCESS_DENIED
                        .appendDescription(
                                " - The supplied access token was not found in the database")
                        .getDescription(),
                responseBody.get("error_description"));
    }
}
