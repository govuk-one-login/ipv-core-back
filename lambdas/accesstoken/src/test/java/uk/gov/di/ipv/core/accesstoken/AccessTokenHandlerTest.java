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
import uk.gov.di.ipv.core.library.exceptions.ClientAuthenticationException;
import uk.gov.di.ipv.core.library.persistence.item.AuthorizationCodeItem;
import uk.gov.di.ipv.core.library.service.AccessTokenService;
import uk.gov.di.ipv.core.library.service.AuthorizationCodeService;
import uk.gov.di.ipv.core.library.service.ConfigurationService;
import uk.gov.di.ipv.core.library.validation.TokenRequestValidator;
import uk.gov.di.ipv.core.library.validation.ValidationResult;

import java.time.Instant;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class AccessTokenHandlerTest {
    private final String TEST_AUTHORIZATION_CODE = "12345";
    private final String TEST_ACCESS_TOKEN = "98765";
    private final ObjectMapper objectMapper = new ObjectMapper();
    private AuthorizationCodeItem authorizationCodeItem;
    private Context context;
    private AccessTokenService mockAccessTokenService;
    private AuthorizationCodeService mockAuthorizationCodeService;
    private TokenRequestValidator mockTokenRequestValidator;

    private AccessTokenHandler handler;
    private TokenResponse tokenResponse;

    @BeforeEach
    void setUp() {
        AccessToken accessToken = new BearerAccessToken();
        tokenResponse = new AccessTokenResponse(new Tokens(accessToken, null));

        mockAccessTokenService = mock(AccessTokenService.class);
        when(mockAccessTokenService.generateAccessToken()).thenReturn(tokenResponse);

        mockAuthorizationCodeService = mock(AuthorizationCodeService.class);
        ConfigurationService mockConfigurationService = mock(ConfigurationService.class);

        mockTokenRequestValidator = mock(TokenRequestValidator.class);

        context = mock(Context.class);

        handler =
                new AccessTokenHandler(
                        mockAccessTokenService,
                        mockAuthorizationCodeService,
                        mockConfigurationService,
                        mockTokenRequestValidator);

        authorizationCodeItem =
                new AuthorizationCodeItem(
                        TEST_AUTHORIZATION_CODE,
                        "12345",
                        "https://callback.example.com",
                        Instant.now().toString());
    }

    @Test
    void shouldReturnAccessTokenOnSuccessfulExchange() throws Exception {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();

        String tokenRequestBody =
                "code=12345&client_assertion=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0IiwiYXVkIjoiYWRtaW4iLCJpc3MiOiJtYXNvbi5tZXRhbXVnLm5ldCIsImV4cCI6MTU3NDUxMjc2NSwiaWF0IjoxNTY2NzM2NzY1LCJqdGkiOiJmN2JmZTMzZi03YmY3LTRlYjQtOGU1OS05OTE3OTliNWViOGEifQ==.EVcCaSqrSNVs3cWdLt-qkoqUk7rPHEOsDHS8yejwxMw&redirect_uri=https://callback.example.com&grant_type=authorization_code&client_id=test_client_id";
        event.setBody(tokenRequestBody);

        when(mockAuthorizationCodeService.getAuthorizationCodeItem(TEST_AUTHORIZATION_CODE))
                .thenReturn(Optional.of(authorizationCodeItem));
        when(mockAccessTokenService.validateAuthorizationGrant(any()))
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
    void shouldReturn400IfAccessTokenServiceDeemsAuthGrantInvalid() throws ParseException {
        when(mockAccessTokenService.validateAuthorizationGrant(any()))
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
                "code=12345&client_assertion=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0IiwiYXVkIjoiYWRtaW4iLCJpc3MiOiJtYXNvbi5tZXRhbXVnLm5ldCIsImV4cCI6MTU3NDUxMjc2NSwiaWF0IjoxNTY2NzM2NzY1LCJqdGkiOiJmN2JmZTMzZi03YmY3LTRlYjQtOGU1OS05OTE3OTliNWViOGEifQ==.EVcCaSqrSNVs3cWdLt-qkoqUk7rPHEOsDHS8yejwxMw&redirect_uri=http://test.com&grant_type=authorization_code&client_id=test_client_id";

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setBody(tokenRequestBody);

        when(mockAccessTokenService.validateAuthorizationGrant(any()))
                .thenReturn(ValidationResult.createValidResult());

        when(mockAuthorizationCodeService.getAuthorizationCodeItem(TEST_AUTHORIZATION_CODE))
                .thenReturn(Optional.empty());

        APIGatewayProxyResponseEvent response = handler.handleRequest(event, context);

        ErrorObject errorResponse = createErrorObjectFromResponse(response.getBody());

        assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        assertEquals(OAuth2Error.INVALID_GRANT.getCode(), errorResponse.getCode());
        assertEquals(
                "The supplied authorization code was not found in the database",
                errorResponse.getDescription());
    }

    @Test
    void shouldReturn400OWhenAuthorisationCodeHasExpired() throws Exception {
        String tokenRequestBody =
                "code=12345&redirect_uri=http://test.com&grant_type=authorization_code&client_id=test_client_id";
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setBody(tokenRequestBody);

        when(mockAccessTokenService.validateAuthorizationGrant(any()))
                .thenReturn(ValidationResult.createValidResult());

        when(mockAuthorizationCodeService.getAuthorizationCodeItem("12345"))
                .thenReturn(Optional.of(authorizationCodeItem));
        when(mockAuthorizationCodeService.isExpired(authorizationCodeItem)).thenReturn(true);

        APIGatewayProxyResponseEvent response = handler.handleRequest(event, context);

        ErrorObject errorResponse = createErrorObjectFromResponse(response.getBody());

        assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        assertEquals(OAuth2Error.INVALID_GRANT.getCode(), errorResponse.getCode());
        assertEquals("Authorization code expired", errorResponse.getDescription());
    }

    @Test
    void shouldReturn401WhenInvalidJwtProvided() throws Exception {
        authorizationCodeItem.setRedirectUrl("https://different.example.com");

        when(mockAccessTokenService.validateAuthorizationGrant(any()))
                .thenReturn(ValidationResult.createValidResult());
        when(mockAuthorizationCodeService.getAuthorizationCodeItem(TEST_AUTHORIZATION_CODE))
                .thenReturn(Optional.of(authorizationCodeItem));
        String tokenRequestBody =
                "code=12345&client_assertion=eyJzdWIiOiIxMjM0IiwiYXVkIjoiYWRtaW4iLCJpc3MiOiJtYXNvbi5tZXRhbXVnLm5ldCIsImV4cCI6MTU3NDUxMjc2NSwiaWF0IjoxNTY2NzM2NzY1LCJqdGkiOiJmN2JmZTMzZi03YmY3LTRlYjQtOGU1OS05OTE3OTliNWViOGEifQ==.EVcCaSqrSNVs3cWdLt-qkoqUk7rPHEOsDHS8yejwxMw&redirect_uri=http://test.com&grant_type=authorization_code&client_id=test_client_id";

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setBody(tokenRequestBody);

        when(mockAccessTokenService.validateAuthorizationGrant(any()))
                .thenReturn(ValidationResult.createValidResult());

        doThrow(new ClientAuthenticationException("error"))
                .when(mockTokenRequestValidator)
                .authenticateClient(any());

        APIGatewayProxyResponseEvent response = handler.handleRequest(event, context);
        ErrorObject errorResponse = createErrorObjectFromResponse(response.getBody());
        assertEquals(HttpStatus.SC_UNAUTHORIZED, response.getStatusCode());
        assertEquals(OAuth2Error.INVALID_CLIENT.getCode(), errorResponse.getCode());
        assertEquals("error", errorResponse.getDescription());
    }

    @Test
    void shouldReturn401WhenJwtMissingFromRequestProvided() throws Exception {
        String tokenRequestBody =
                "code=12345&redirect_uri=http://test.com&grant_type=authorization_code&client_id=test_client_id";

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setBody(tokenRequestBody);

        when(mockAccessTokenService.validateAuthorizationGrant(any()))
                .thenReturn(ValidationResult.createValidResult());

        doThrow(new ClientAuthenticationException("error"))
                .when(mockTokenRequestValidator)
                .authenticateClient(any());

        APIGatewayProxyResponseEvent response = handler.handleRequest(event, context);
        ErrorObject errorResponse = createErrorObjectFromResponse(response.getBody());
        assertEquals(HTTPResponse.SC_UNAUTHORIZED, response.getStatusCode());
        assertEquals(OAuth2Error.INVALID_CLIENT.getCode(), errorResponse.getCode());
        assertEquals("error", errorResponse.getDescription());
    }

    @Test
    void shouldReturn400WhenAuthCodeIsUsedMoreThanOnce() throws Exception {
        String tokenRequestBody =
                "code=12345&redirect_uri=http://test.com&grant_type=authorization_code&client_id=test_client_id";

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setBody(tokenRequestBody);

        authorizationCodeItem.setIssuedAccessToken(TEST_ACCESS_TOKEN);
        authorizationCodeItem.setExchangeDateTime(Instant.now().toString());

        when(mockAuthorizationCodeService.getAuthorizationCodeItem(TEST_AUTHORIZATION_CODE))
                .thenReturn(Optional.of(authorizationCodeItem));

        when(mockAccessTokenService.validateAuthorizationGrant(any()))
                .thenReturn(ValidationResult.createValidResult());

        APIGatewayProxyResponseEvent response = handler.handleRequest(event, context);

        verify(mockAccessTokenService).revokeAccessToken(TEST_ACCESS_TOKEN);

        ErrorObject errorResponse = createErrorObjectFromResponse(response.getBody());

        assertEquals(HTTPResponse.SC_BAD_REQUEST, response.getStatusCode());
        assertEquals(OAuth2Error.INVALID_GRANT.getCode(), errorResponse.getCode());
        assertEquals("Authorization code used too many times", errorResponse.getDescription());
    }

    @Test
    void shouldReturn400WhenRevokingAccessTokenFails() throws Exception {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        String tokenRequestBody =
                "code=12345&redirect_uri=http://example.com&grant_type=authorization_code&client_id=test_client_id";
        event.setBody(tokenRequestBody);

        authorizationCodeItem.setIssuedAccessToken(TEST_ACCESS_TOKEN);
        authorizationCodeItem.setExchangeDateTime(Instant.now().toString());

        when(mockAuthorizationCodeService.getAuthorizationCodeItem(TEST_AUTHORIZATION_CODE))
                .thenReturn(Optional.of(authorizationCodeItem));

        when(mockAccessTokenService.validateAuthorizationGrant(any()))
                .thenReturn(ValidationResult.createValidResult());

        String errorMessage = "Failed to revoke access token";
        doThrow(new IllegalArgumentException(errorMessage))
                .when(mockAccessTokenService)
                .revokeAccessToken(any(String.class));

        APIGatewayProxyResponseEvent response = handler.handleRequest(event, context);

        verify(mockAccessTokenService)
                .revokeAccessToken(authorizationCodeItem.getIssuedAccessToken());

        ErrorObject errorResponse = createErrorObjectFromResponse(response.getBody());

        assertEquals(HTTPResponse.SC_BAD_REQUEST, response.getStatusCode());
        assertEquals(OAuth2Error.INVALID_GRANT.getCode(), errorResponse.getCode());
        assertEquals(errorMessage, errorResponse.getDescription());
    }

    @Test
    void shouldReturn400WhenRedirectURLsDoNotMatch() throws Exception {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();

        String tokenRequestBody =
                "redirect_uri=https://different.example.com&code=12345&client_assertion=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0IiwiYXVkIjoiYWRtaW4iLCJpc3MiOiJtYXNvbi5tZXRhbXVnLm5ldCIsImV4cCI6MTU3NDUxMjc2NSwiaWF0IjoxNTY2NzM2NzY1LCJqdGkiOiJmN2JmZTMzZi03YmY3LTRlYjQtOGU1OS05OTE3OTliNWViOGEifQ==.EVcCaSqrSNVs3cWdLt-qkoqUk7rPHEOsDHS8yejwxMw&grant_type=authorization_code&client_id=test_client_id";
        event.setBody(tokenRequestBody);

        when(mockAuthorizationCodeService.getAuthorizationCodeItem(TEST_AUTHORIZATION_CODE))
                .thenReturn(Optional.of(authorizationCodeItem));
        when(mockAccessTokenService.validateAuthorizationGrant(any()))
                .thenReturn(ValidationResult.createValidResult());

        APIGatewayProxyResponseEvent response = handler.handleRequest(event, context);

        ErrorObject errorResponse = createErrorObjectFromResponse(response.getBody());

        assertEquals(HTTPResponse.SC_BAD_REQUEST, response.getStatusCode());
        assertEquals(OAuth2Error.INVALID_GRANT.getCode(), errorResponse.getCode());
        assertEquals(
                "Redirect URL in token request does not match redirect URL received in auth code request",
                errorResponse.getDescription());
    }

    private ErrorObject createErrorObjectFromResponse(String responseBody) throws ParseException {
        HTTPResponse httpErrorResponse = new HTTPResponse(HttpStatus.SC_BAD_REQUEST);
        httpErrorResponse.setContentType(ContentType.APPLICATION_JSON.getType());
        httpErrorResponse.setContent(responseBody);
        return ErrorObject.parse(httpErrorResponse);
    }
}
