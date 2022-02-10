package uk.gov.di.ipv.core.accesstoken;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.common.contenttype.ContentType;
import com.nimbusds.oauth2.sdk.AccessTokenResponse;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.GrantType;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.Tokens;
import org.apache.http.HttpStatus;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.ipv.core.library.persistence.item.AuthorizationCodeItem;
import uk.gov.di.ipv.core.library.service.AccessTokenService;
import uk.gov.di.ipv.core.library.service.AuthorizationCodeService;
import uk.gov.di.ipv.core.library.service.ConfigurationService;
import uk.gov.di.ipv.core.library.validation.ValidationResult;

import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class AccessTokenHandlerTest {
    private final ObjectMapper objectMapper = new ObjectMapper();
    private Context context;
    private AccessTokenService mockAccessTokenService;
    private AuthorizationCodeService mockAuthorizationCodeService;

    private AccessTokenHandler handler;
    private TokenResponse tokenResponse;

    @BeforeEach
    void setUp() {
        AccessToken accessToken = new BearerAccessToken();
        tokenResponse = new AccessTokenResponse(new Tokens(accessToken, null));

        mockAccessTokenService = mock(AccessTokenService.class);
        when(mockAccessTokenService.generateAccessToken(any())).thenReturn(tokenResponse);

        mockAuthorizationCodeService = mock(AuthorizationCodeService.class);
        ConfigurationService mockConfigurationService = mock(ConfigurationService.class);

        context = mock(Context.class);

        handler =
                new AccessTokenHandler(
                        mockAccessTokenService,
                        mockAuthorizationCodeService,
                        mockConfigurationService);
    }

    @Test
    void shouldReturnAccessTokenOnSuccessfulExchange() throws Exception {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        String tokenRequestBody =
                "code=12345&redirect_uri=https://callback.example.com&grant_type=authorization_code&client_id=test_client_id";
        event.setBody(tokenRequestBody);

        AuthorizationCodeItem authorizationCodeItem = new AuthorizationCodeItem();
        authorizationCodeItem.setRedirectUrl("https://callback.example.com");
        authorizationCodeItem.setAuthCode("random_auth_code");
        authorizationCodeItem.setIpvSessionId("12345");

        when(mockAuthorizationCodeService.getAuthorizationCodeItem("12345"))
                .thenReturn(Optional.of(authorizationCodeItem));
        when(mockAccessTokenService.validateTokenRequest(any()))
                .thenReturn(ValidationResult.createValidResult());

        APIGatewayProxyResponseEvent response = handler.handleRequest(event, context);

        Map<String, Object> responseBody =
                objectMapper.readValue(response.getBody(), new TypeReference<>() {});
        assertEquals(
                ContentType.APPLICATION_JSON.getType(), response.getHeaders().get("Content-Type"));
        assertEquals(200, response.getStatusCode());
        assertEquals(
                tokenResponse.toSuccessResponse().getTokens().getAccessToken().getValue(),
                responseBody.get("access_token").toString());
    }

    @Test
    void shouldReturn400WhenInvalidTokenRequestProvided() throws Exception {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        String invalidTokenRequest = "invalid-token-request";
        event.setBody(invalidTokenRequest);

        APIGatewayProxyResponseEvent response = handler.handleRequest(event, context);

        ErrorObject errorResponse = createErrorObjectFromResponse(response.getBody());

        assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        assertEquals(OAuth2Error.INVALID_REQUEST.getCode(), errorResponse.getCode());
        assertEquals(
                OAuth2Error.INVALID_REQUEST.getDescription() + ": Missing grant_type parameter",
                errorResponse.getDescription());
    }

    @Test
    void shouldReturn400WhenInvalidGrantTypeProvided() throws Exception {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        String tokenRequestBody =
                "code=12345&redirect_uri=http://test.com&grant_type="
                        + GrantType.IMPLICIT.getValue()
                        + "&client_id=test_client_id";

        event.setBody(tokenRequestBody);

        APIGatewayProxyResponseEvent response = handler.handleRequest(event, context);

        ErrorObject errorResponse = createErrorObjectFromResponse(response.getBody());

        assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        assertEquals(OAuth2Error.UNSUPPORTED_GRANT_TYPE.getCode(), errorResponse.getCode());
        assertEquals(
                OAuth2Error.UNSUPPORTED_GRANT_TYPE.getDescription(),
                errorResponse.getDescription());
    }

    @Test
    void shouldReturn400IfAccessTokenServiceDeemsRequestInvalid() throws ParseException {
        when(mockAccessTokenService.validateTokenRequest(any()))
                .thenReturn(new ValidationResult<>(false, OAuth2Error.UNSUPPORTED_GRANT_TYPE));

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        String tokenRequestBody =
                "code=12345&redirect_uri=http://test.com&grant_type=authorization_code&client_id=test_client_id";
        event.setBody(tokenRequestBody);

        APIGatewayProxyResponseEvent response = handler.handleRequest(event, context);

        ErrorObject errorResponse = createErrorObjectFromResponse(response.getBody());

        assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        assertEquals(OAuth2Error.UNSUPPORTED_GRANT_TYPE.getCode(), errorResponse.getCode());
        assertEquals(
                OAuth2Error.UNSUPPORTED_GRANT_TYPE.getDescription(),
                errorResponse.getDescription());
    }

    @Test
    void shouldReturn400OWhenInvalidAuthorisationCodeProvided() throws Exception {
        String tokenRequestBody =
                "code=12345&redirect_uri=http://test.com&grant_type=authorization_code&client_id=test_client_id";
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setBody(tokenRequestBody);

        when(mockAccessTokenService.validateTokenRequest(any()))
                .thenReturn(ValidationResult.createValidResult());
        when(mockAuthorizationCodeService.getAuthorizationCodeItem("12345"))
                .thenReturn(Optional.empty());

        APIGatewayProxyResponseEvent response = handler.handleRequest(event, context);

        ErrorObject errorResponse = createErrorObjectFromResponse(response.getBody());

        assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        assertEquals(OAuth2Error.INVALID_GRANT.getCode(), errorResponse.getCode());
        assertEquals(OAuth2Error.INVALID_GRANT.getDescription(), errorResponse.getDescription());
    }

    @Test
    void shouldReturn400WhenRedirectUrlInAuthGrantDoesNotMatchThatSuppliedToAuthEndpoint()
            throws ParseException {
        AuthorizationCodeItem authorizationCodeItem = new AuthorizationCodeItem();
        authorizationCodeItem.setRedirectUrl("https://different.example.com");
        authorizationCodeItem.setAuthCode("random_auth_code");
        authorizationCodeItem.setIpvSessionId("12345");

        when(mockAccessTokenService.validateTokenRequest(any()))
                .thenReturn(ValidationResult.createValidResult());
        when(mockAuthorizationCodeService.getAuthorizationCodeItem("12345"))
                .thenReturn(Optional.of(authorizationCodeItem));

        String tokenRequestBody =
                "code=12345&redirect_uri=http://test.com&grant_type=authorization_code&client_id=test_client_id";
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setBody(tokenRequestBody);

        APIGatewayProxyResponseEvent response = handler.handleRequest(event, context);

        ErrorObject errorResponse = createErrorObjectFromResponse(response.getBody());

        assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        assertEquals(OAuth2Error.INVALID_REQUEST.getCode(), errorResponse.getCode());
        assertEquals(OAuth2Error.INVALID_REQUEST.getDescription(), errorResponse.getDescription());
    }

    private ErrorObject createErrorObjectFromResponse(String responseBody) throws ParseException {
        HTTPResponse httpErrorResponse = new HTTPResponse(HttpStatus.SC_BAD_REQUEST);
        httpErrorResponse.setContentType(ContentType.APPLICATION_JSON.getType());
        httpErrorResponse.setContent(responseBody);
        return ErrorObject.parse(httpErrorResponse);
    }
}
