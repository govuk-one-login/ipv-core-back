package uk.gov.di.ipv.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import org.apache.http.HttpStatus;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.ipv.domain.ErrorResponse;
import uk.gov.di.ipv.service.AuthorizationCodeService;

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class AuthorizationHandlerTest {
    private static final Map<String, String> TEST_EVENT_HEADERS = Map.of("ipv-session-id", "12345");

    private final Context context = mock(Context.class);
    private AuthorizationCodeService mockAuthorizationCodeService;

    private AuthorizationHandler handler;
    private AuthorizationCode authorizationCode;

    @BeforeEach
    void setUp() {
        mockAuthorizationCodeService = mock(AuthorizationCodeService.class);

        authorizationCode = new AuthorizationCode();
        when(mockAuthorizationCodeService.generateAuthorizationCode())
                .thenReturn(authorizationCode);

        handler = new AuthorizationHandler(mockAuthorizationCodeService);
    }

    @Test
    void shouldReturn200OnSuccessfulOauthRequest() {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        Map<String, String> params = new HashMap<>();
        params.put(OAuth2RequestParams.REDIRECT_URI, "http://example.com");
        params.put(OAuth2RequestParams.CLIENT_ID, "12345");
        params.put(OAuth2RequestParams.RESPONSE_TYPE, "code");
        params.put(OAuth2RequestParams.SCOPE, "openid");
        event.setQueryStringParameters(params);

        event.setHeaders(TEST_EVENT_HEADERS);

        APIGatewayProxyResponseEvent response = handler.handleRequest(event, context);

        assertEquals(HttpStatus.SC_OK, response.getStatusCode());
    }

    @Test
    void shouldReturnAuthResponseOnSuccessfulOauthRequest() throws Exception {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        Map<String, String> params = new HashMap<>();
        params.put(OAuth2RequestParams.REDIRECT_URI, "http://example.com");
        params.put(OAuth2RequestParams.CLIENT_ID, "12345");
        params.put(OAuth2RequestParams.RESPONSE_TYPE, "code");
        params.put(OAuth2RequestParams.SCOPE, "openid");
        event.setQueryStringParameters(params);

        event.setHeaders(TEST_EVENT_HEADERS);

        APIGatewayProxyResponseEvent response = handler.handleRequest(event, context);

        ObjectMapper objectMapper = new ObjectMapper();
        Map<String, Object> responseBody = objectMapper.readValue(response.getBody(), Map.class);
        Map<String, String> authCode = (Map) responseBody.get("code");

        verify(mockAuthorizationCodeService)
                .persistAuthorizationCode(authCode.get("value"), "12345");
        assertEquals(authorizationCode.toString(), authCode.get("value"));
    }

    @Test
    void shouldReturn400OnMissingRedirectUriParam() throws Exception {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        Map<String, String> params = new HashMap<>();
        params.put(OAuth2RequestParams.CLIENT_ID, "12345");
        params.put(OAuth2RequestParams.RESPONSE_TYPE, "code");
        params.put(OAuth2RequestParams.SCOPE, "openid");
        event.setQueryStringParameters(params);

        event.setHeaders(TEST_EVENT_HEADERS);

        APIGatewayProxyResponseEvent response = handler.handleRequest(event, context);

        ObjectMapper objectMapper = new ObjectMapper();
        Map responseBody = objectMapper.readValue(response.getBody(), Map.class);

        assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        assertEquals(
                ErrorResponse.FAILED_TO_PARSE_OAUTH_QUERY_STRING_PARAMETERS.getCode(),
                responseBody.get("code"));
        assertEquals(
                ErrorResponse.FAILED_TO_PARSE_OAUTH_QUERY_STRING_PARAMETERS.getMessage(),
                responseBody.get("message"));
    }

    @Test
    void shouldReturn400OnMissingClientIdParam() throws Exception {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        Map<String, String> params = new HashMap<>();
        params.put(OAuth2RequestParams.REDIRECT_URI, "http://example.com");
        params.put(OAuth2RequestParams.RESPONSE_TYPE, "code");
        params.put(OAuth2RequestParams.SCOPE, "openid");
        event.setQueryStringParameters(params);

        event.setHeaders(TEST_EVENT_HEADERS);

        APIGatewayProxyResponseEvent response = handler.handleRequest(event, context);

        ObjectMapper objectMapper = new ObjectMapper();
        Map responseBody = objectMapper.readValue(response.getBody(), Map.class);

        assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        assertEquals(
                ErrorResponse.FAILED_TO_PARSE_OAUTH_QUERY_STRING_PARAMETERS.getCode(),
                responseBody.get("code"));
        assertEquals(
                ErrorResponse.FAILED_TO_PARSE_OAUTH_QUERY_STRING_PARAMETERS.getMessage(),
                responseBody.get("message"));
    }

    @Test
    void shouldReturn400OnMissingResponseTypeParam() throws Exception {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        Map<String, String> params = new HashMap<>();
        params.put(OAuth2RequestParams.REDIRECT_URI, "http://example.com");
        params.put(OAuth2RequestParams.CLIENT_ID, "12345");
        params.put(OAuth2RequestParams.SCOPE, "openid");
        event.setQueryStringParameters(params);

        event.setHeaders(TEST_EVENT_HEADERS);

        APIGatewayProxyResponseEvent response = handler.handleRequest(event, context);

        ObjectMapper objectMapper = new ObjectMapper();
        Map responseBody = objectMapper.readValue(response.getBody(), Map.class);

        assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        assertEquals(
                ErrorResponse.FAILED_TO_PARSE_OAUTH_QUERY_STRING_PARAMETERS.getCode(),
                responseBody.get("code"));
        assertEquals(
                ErrorResponse.FAILED_TO_PARSE_OAUTH_QUERY_STRING_PARAMETERS.getMessage(),
                responseBody.get("message"));
    }

    @Test
    void shouldReturn400OnMissingScopeParam() throws Exception {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        Map<String, String> params = new HashMap<>();
        params.put(OAuth2RequestParams.REDIRECT_URI, "http://example.com");
        params.put(OAuth2RequestParams.CLIENT_ID, "12345");
        params.put(OAuth2RequestParams.RESPONSE_TYPE, "code");
        event.setQueryStringParameters(params);

        event.setHeaders(TEST_EVENT_HEADERS);

        APIGatewayProxyResponseEvent response = handler.handleRequest(event, context);

        ObjectMapper objectMapper = new ObjectMapper();
        Map responseBody = objectMapper.readValue(response.getBody(), Map.class);

        assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        assertEquals(
                ErrorResponse.FAILED_TO_PARSE_OAUTH_QUERY_STRING_PARAMETERS.getCode(),
                responseBody.get("code"));
        assertEquals(
                ErrorResponse.FAILED_TO_PARSE_OAUTH_QUERY_STRING_PARAMETERS.getMessage(),
                responseBody.get("message"));
    }

    @Test
    void shouldReturn400OnMissingQueryParameters() throws Exception {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();

        event.setHeaders(TEST_EVENT_HEADERS);

        APIGatewayProxyResponseEvent response = handler.handleRequest(event, context);

        ObjectMapper objectMapper = new ObjectMapper();
        Map responseBody = objectMapper.readValue(response.getBody(), Map.class);

        assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        assertEquals(ErrorResponse.MISSING_QUERY_PARAMETERS.getCode(), responseBody.get("code"));
        assertEquals(
                ErrorResponse.MISSING_QUERY_PARAMETERS.getMessage(), responseBody.get("message"));
    }

    @Test
    void shouldReturn400OnMissingSessionIdHeader() throws Exception {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        Map<String, String> params = new HashMap<>();
        params.put(OAuth2RequestParams.REDIRECT_URI, "http://example.com");
        params.put(OAuth2RequestParams.CLIENT_ID, "12345");
        params.put(OAuth2RequestParams.RESPONSE_TYPE, "code");
        params.put(OAuth2RequestParams.SCOPE, "openid");
        event.setQueryStringParameters(params);

        event.setHeaders(Collections.emptyMap());

        APIGatewayProxyResponseEvent response = handler.handleRequest(event, context);

        ObjectMapper objectMapper = new ObjectMapper();
        Map responseBody = objectMapper.readValue(response.getBody(), Map.class);

        assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        assertEquals(ErrorResponse.MISSING_IPV_SESSION_ID.getCode(), responseBody.get("code"));
        assertEquals(
                ErrorResponse.MISSING_IPV_SESSION_ID.getMessage(), responseBody.get("message"));
    }
}
