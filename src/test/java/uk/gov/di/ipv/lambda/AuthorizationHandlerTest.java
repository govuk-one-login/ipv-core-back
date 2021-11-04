package uk.gov.di.ipv.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.ipv.entity.ErrorResponse;
import uk.gov.di.ipv.service.AuthorizationCodeService;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class AuthorizationHandlerTest {
    private final Context context = mock(Context.class);
    private final AuthorizationCodeService authorizationCodeService = mock(AuthorizationCodeService.class);

    private AuthorizationHandler handler;
    private AuthorizationCode authorizationCode;

    @BeforeEach
    public void setUp() {
        authorizationCode = new AuthorizationCode();
        when(authorizationCodeService.generateAuthorisationCode()).thenReturn(authorizationCode);

        handler = new AuthorizationHandler(authorizationCodeService);
    }

    @Test
    public void shouldReturn200OnSuccessfulOauthRequest(){
        final APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        final Map<String, String> params = new HashMap<>();
        params.put("redirect_uri", "http://test.co.uk");
        params.put("client_id", "12345");
        params.put("response_type", "code");
        params.put("scope", "openid");
        event.setQueryStringParameters(params);

        final APIGatewayProxyResponseEvent response = handler.handleRequest(event, context);

        assertEquals(200, response.getStatusCode());
    }

    @Test
    public void shouldReturnAuthResponseOnSuccessfulOauthRequest() throws Exception {
        final APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        final Map<String, String> params = new HashMap<>();
        params.put("redirect_uri", "http://test.co.uk");
        params.put("client_id", "12345");
        params.put("response_type", "code");
        params.put("scope", "openid");
        event.setQueryStringParameters(params);

        final APIGatewayProxyResponseEvent response = handler.handleRequest(event, context);

        final ObjectMapper objectMapper = new ObjectMapper();
        final Map<String, Object> responseBody = objectMapper.readValue(response.getBody(), Map.class);
        final Map<String, String> authCode = (Map) responseBody.get("authorizationCode");

        assertEquals(authorizationCode.toString(), authCode.get("value"));
        assertEquals(event.getQueryStringParameters().get("redirect_uri"), responseBody.get("redirectionURI"));
    }

    @Test
    public void shouldReturn400OnMissingRedirectUriParam() throws Exception {
        final APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        final Map<String, String> params = new HashMap<>();
        params.put("client_id", "12345");
        params.put("response_type", "code");
        params.put("scope", "openid");
        event.setQueryStringParameters(params);

        final APIGatewayProxyResponseEvent response = handler.handleRequest(event, context);

        final ObjectMapper objectMapper = new ObjectMapper();
        final Map responseBody = objectMapper.readValue(response.getBody(), Map.class);

        assertEquals(400, response.getStatusCode());
        assertEquals(ErrorResponse.ERROR_1001.getCode(), responseBody.get("code"));
        assertEquals(ErrorResponse.ERROR_1001.getMessage(), responseBody.get("message"));
    }

    @Test
    public void shouldReturn400OnMissingClientIdParam() throws Exception {
        final APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        final Map<String, String> params = new HashMap<>();
        params.put("redirect_uri", "http://test.co.uk");
        params.put("response_type", "code");
        params.put("scope", "openid");
        event.setQueryStringParameters(params);

        final APIGatewayProxyResponseEvent response = handler.handleRequest(event, context);

        final ObjectMapper objectMapper = new ObjectMapper();
        final Map responseBody = objectMapper.readValue(response.getBody(), Map.class);

        assertEquals(400, response.getStatusCode());
        assertEquals(ErrorResponse.ERROR_1001.getCode(), responseBody.get("code"));
        assertEquals(ErrorResponse.ERROR_1001.getMessage(), responseBody.get("message"));
    }

    @Test
    public void shouldReturn400OnMissingResponseTypeParam() throws Exception {
        final APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        final Map<String, String> params = new HashMap<>();
        params.put("redirect_uri", "http://test.co.uk");
        params.put("client_id", "12345");
        params.put("scope", "openid");
        event.setQueryStringParameters(params);

        final APIGatewayProxyResponseEvent response = handler.handleRequest(event, context);

        final ObjectMapper objectMapper = new ObjectMapper();
        final Map responseBody = objectMapper.readValue(response.getBody(), Map.class);

        assertEquals(400, response.getStatusCode());
        assertEquals(ErrorResponse.ERROR_1001.getCode(), responseBody.get("code"));
        assertEquals(ErrorResponse.ERROR_1001.getMessage(), responseBody.get("message"));
    }

    @Test
    public void shouldReturn400OnMissingScopeParam() throws Exception {
        final APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        final Map<String, String> params = new HashMap<>();
        params.put("redirect_uri", "http://test.co.uk");
        params.put("client_id", "12345");
        params.put("response_type", "code");
        event.setQueryStringParameters(params);

        final APIGatewayProxyResponseEvent response = handler.handleRequest(event, context);

        final ObjectMapper objectMapper = new ObjectMapper();
        final Map responseBody = objectMapper.readValue(response.getBody(), Map.class);

        assertEquals(400, response.getStatusCode());
        assertEquals(ErrorResponse.ERROR_1001.getCode(), responseBody.get("code"));
        assertEquals(ErrorResponse.ERROR_1001.getMessage(), responseBody.get("message"));
    }

    @Test
    public void shouldReturn400OnMissingQueryParameters() throws Exception {
        final APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();

        final APIGatewayProxyResponseEvent response = handler.handleRequest(event, context);

        final ObjectMapper objectMapper = new ObjectMapper();
        final Map responseBody = objectMapper.readValue(response.getBody(), Map.class);

        assertEquals(400, response.getStatusCode());
        assertEquals(ErrorResponse.ERROR_1000.getCode(), responseBody.get("code"));
        assertEquals(ErrorResponse.ERROR_1000.getMessage(), responseBody.get("message"));
    }
}
