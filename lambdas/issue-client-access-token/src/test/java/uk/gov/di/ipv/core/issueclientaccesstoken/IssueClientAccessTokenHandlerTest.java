package uk.gov.di.ipv.core.issueclientaccesstoken;

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
import uk.gov.di.ipv.core.issueclientaccesstoken.exception.ClientAuthenticationException;
import uk.gov.di.ipv.core.issueclientaccesstoken.service.AccessTokenService;
import uk.gov.di.ipv.core.issueclientaccesstoken.validation.TokenRequestValidator;
import uk.gov.di.ipv.core.library.dto.AuthorizationCodeMetadata;
import uk.gov.di.ipv.core.library.exceptions.IpvSessionNotFoundException;
import uk.gov.di.ipv.core.library.helpers.SecureTokenHelper;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.ClientOAuthSessionDetailsService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.validation.ValidationResult;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.AUTH_CODE_EXPIRY_SECONDS;

class IssueClientAccessTokenHandlerTest {
    private final String TEST_AUTHORIZATION_CODE = "12345";
    private final String TEST_ACCESS_TOKEN = "98765";
    private final String TEST_REDIRECT_URL = "https://callback.example.com";
    private final String TEST_SESSION_ID = "test-session-id";
    private final ObjectMapper objectMapper = new ObjectMapper();
    private IpvSessionItem mockSessionItem;
    private Context context;
    private ConfigService mockConfigService;
    private AccessTokenService mockAccessTokenService;
    private IpvSessionService mockSessionService;
    private ClientOAuthSessionDetailsService mockClientOAuthSessionService;
    private TokenRequestValidator mockTokenRequestValidator;

    private IssueClientAccessTokenHandler handler;
    private TokenResponse tokenResponse;

    @BeforeEach
    void setUp() {
        AccessToken accessToken = new BearerAccessToken();
        tokenResponse = new AccessTokenResponse(new Tokens(accessToken, null));

        mockAccessTokenService = mock(AccessTokenService.class);
        when(mockAccessTokenService.generateAccessToken()).thenReturn(tokenResponse);

        mockConfigService = mock(ConfigService.class);
        when(mockConfigService.getParameter(AUTH_CODE_EXPIRY_SECONDS)).thenReturn("3600");

        mockSessionService = mock(IpvSessionService.class);
        mockClientOAuthSessionService = mock(ClientOAuthSessionDetailsService.class);

        mockTokenRequestValidator = mock(TokenRequestValidator.class);

        context = mock(Context.class);

        handler =
                new IssueClientAccessTokenHandler(
                        mockAccessTokenService,
                        mockSessionService,
                        mockConfigService,
                        mockClientOAuthSessionService,
                        mockTokenRequestValidator);

        AuthorizationCodeMetadata mockAuthorizationCodeMetadata = new AuthorizationCodeMetadata();
        mockAuthorizationCodeMetadata.setCreationDateTime(Instant.now().toString());
        mockAuthorizationCodeMetadata.setRedirectUrl(TEST_REDIRECT_URL);

        mockSessionItem = new IpvSessionItem();
        mockSessionItem.setIpvSessionId(TEST_SESSION_ID);
        mockSessionItem.setAuthorizationCode(TEST_AUTHORIZATION_CODE);
        mockSessionItem.setAuthorizationCodeMetadata(mockAuthorizationCodeMetadata);
        mockSessionItem.setFeatureSet("someCoolNewThing");
    }

    @Test
    void shouldReturnAccessTokenOnSuccessfulExchange() throws Exception {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        String tokenRequestBody =
                "code="
                        + TEST_AUTHORIZATION_CODE
                        + "&client_assertion=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0IiwiYXVkIjoiYWRtaW4iLCJpc3MiOiJtYXNvbi5tZXRhbXVnLm5ldCIsImV4cCI6MTU3NDUxMjc2NSwiaWF0IjoxNTY2NzM2NzY1LCJqdGkiOiJmN2JmZTMzZi03YmY3LTRlYjQtOGU1OS05OTE3OTliNWViOGEifQ==.EVcCaSqrSNVs3cWdLt-qkoqUk7rPHEOsDHS8yejwxMw&redirect_uri=" // pragma: allowlist secret
                        + TEST_REDIRECT_URL
                        + "&grant_type=authorization_code&client_id=test_client_id";
        event.setBody(tokenRequestBody);

        when(mockAccessTokenService.validateAuthorizationGrant(any()))
                .thenReturn(ValidationResult.createValidResult());
        when(mockSessionService.getIpvSessionByAuthorizationCode(TEST_AUTHORIZATION_CODE))
                .thenReturn(mockSessionItem);
        when(mockClientOAuthSessionService.getClientOAuthSession(any()))
                .thenReturn(getClientOAuthSessionItem());
        when(mockClientOAuthSessionService.getClientOAuthSession(any()))
                .thenReturn(getClientOAuthSessionItem());

        APIGatewayProxyResponseEvent response = handler.handleRequest(event, context);

        Map<String, Object> responseBody =
                objectMapper.readValue(response.getBody(), new TypeReference<>() {});
        assertEquals(
                ContentType.APPLICATION_JSON.getType(), response.getHeaders().get("Content-Type"));
        assertEquals(200, response.getStatusCode());
        assertEquals(
                tokenResponse.toSuccessResponse().getTokens().getAccessToken().getValue(),
                responseBody.get("access_token").toString());

        verify(mockConfigService).setFeatureSet(List.of("someCoolNewThing"));
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
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        String tokenRequestBody =
                "code=12345&redirect_uri=http://test.com&grant_type=authorization_code&client_id=test_client_id";
        event.setBody(tokenRequestBody);

        when(mockAccessTokenService.validateAuthorizationGrant(any()))
                .thenReturn(new ValidationResult<>(false, OAuth2Error.UNSUPPORTED_GRANT_TYPE));

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
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        String tokenRequestBody =
                "code="
                        + TEST_AUTHORIZATION_CODE
                        + "&client_assertion=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0IiwiYXVkIjoiYWRtaW4iLCJpc3MiOiJtYXNvbi5tZXRhbXVnLm5ldCIsImV4cCI6MTU3NDUxMjc2NSwiaWF0IjoxNTY2NzM2NzY1LCJqdGkiOiJmN2JmZTMzZi03YmY3LTRlYjQtOGU1OS05OTE3OTliNWViOGEifQ==.EVcCaSqrSNVs3cWdLt-qkoqUk7rPHEOsDHS8yejwxMw&redirect_uri=http://test.com&grant_type=authorization_code&client_id=test_client_id"; // pragma: allowlist secret
        event.setBody(tokenRequestBody);

        when(mockAccessTokenService.validateAuthorizationGrant(any()))
                .thenReturn(ValidationResult.createValidResult());
        when(mockSessionService.getIpvSessionByAuthorizationCode(TEST_AUTHORIZATION_CODE))
                .thenThrow(
                        new IpvSessionNotFoundException(
                                "The supplied authorization code was not found in the database"));

        APIGatewayProxyResponseEvent response = handler.handleRequest(event, context);

        ErrorObject errorResponse = createErrorObjectFromResponse(response.getBody());
        assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        assertEquals(OAuth2Error.INVALID_GRANT.getCode(), errorResponse.getCode());
        assertEquals(
                "The supplied authorization code was not found in the database",
                errorResponse.getDescription());
    }

    @Test
    void shouldReturn400WhenIpvSessionNotFoundForAuthCode() throws Exception {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        String tokenRequestBody =
                "code="
                        + TEST_AUTHORIZATION_CODE
                        + "&client_assertion=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0IiwiYXVkIjoiYWRtaW4iLCJpc3MiOiJtYXNvbi5tZXRhbXVnLm5ldCIsImV4cCI6MTU3NDUxMjc2NSwiaWF0IjoxNTY2NzM2NzY1LCJqdGkiOiJmN2JmZTMzZi03YmY3LTRlYjQtOGU1OS05OTE3OTliNWViOGEifQ==.EVcCaSqrSNVs3cWdLt-qkoqUk7rPHEOsDHS8yejwxMw&redirect_uri=http://test.com&grant_type=authorization_code&client_id=test_client_id"; // pragma: allowlist secret
        event.setBody(tokenRequestBody);

        when(mockAccessTokenService.validateAuthorizationGrant(any()))
                .thenReturn(ValidationResult.createValidResult());
        when(mockSessionService.getIpvSessionByAuthorizationCode(TEST_AUTHORIZATION_CODE))
                .thenThrow(new IpvSessionNotFoundException("Error"));

        APIGatewayProxyResponseEvent response = handler.handleRequest(event, context);

        ErrorObject errorResponse = createErrorObjectFromResponse(response.getBody());
        assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        assertEquals(OAuth2Error.INVALID_GRANT.getCode(), errorResponse.getCode());
        assertEquals("Error", errorResponse.getDescription());
    }

    @Test
    void shouldReturn400WhenAuthorisationCodeHasExpired() throws Exception {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        String tokenRequestBody =
                "code="
                        + TEST_AUTHORIZATION_CODE
                        + "&redirect_uri=http://test.com&grant_type=authorization_code&client_id=test_client_id";
        event.setBody(tokenRequestBody);

        when(mockConfigService.getParameter(AUTH_CODE_EXPIRY_SECONDS)).thenReturn("0");
        when(mockAccessTokenService.validateAuthorizationGrant(any()))
                .thenReturn(ValidationResult.createValidResult());
        when(mockSessionService.getIpvSessionByAuthorizationCode(TEST_AUTHORIZATION_CODE))
                .thenReturn(mockSessionItem);
        when(mockClientOAuthSessionService.getClientOAuthSession(any()))
                .thenReturn(getClientOAuthSessionItem());

        APIGatewayProxyResponseEvent response = handler.handleRequest(event, context);

        ErrorObject errorResponse = createErrorObjectFromResponse(response.getBody());
        assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        assertEquals(OAuth2Error.INVALID_GRANT.getCode(), errorResponse.getCode());
        assertEquals("Authorization code expired", errorResponse.getDescription());
    }

    @Test
    void shouldReturn401WhenInvalidJwtProvided() throws Exception {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        String tokenRequestBody =
                "code="
                        + TEST_AUTHORIZATION_CODE
                        + "&client_assertion=eyJzdWIiOiIxMjM0IiwiYXVkIjoiYWRtaW4iLCJpc3MiOiJtYXNvbi5tZXRhbXVnLm5ldCIsImV4cCI6MTU3NDUxMjc2NSwiaWF0IjoxNTY2NzM2NzY1LCJqdGkiOiJmN2JmZTMzZi03YmY3LTRlYjQtOGU1OS05OTE3OTliNWViOGEifQ==.EVcCaSqrSNVs3cWdLt-qkoqUk7rPHEOsDHS8yejwxMw&redirect_uri=http://test.com&grant_type=authorization_code&client_id=test_client_id"; // pragma: allowlist secret
        event.setBody(tokenRequestBody);

        when(mockAccessTokenService.validateAuthorizationGrant(any()))
                .thenReturn(ValidationResult.createValidResult());
        when(mockSessionService.getIpvSessionByAuthorizationCode(TEST_AUTHORIZATION_CODE))
                .thenReturn(mockSessionItem);
        doThrow(new ClientAuthenticationException("error"))
                .when(mockTokenRequestValidator)
                .authenticateClient(any());

        APIGatewayProxyResponseEvent response = handler.handleRequest(event, context);

        ErrorObject errorResponse = createErrorObjectFromResponse(response.getBody());
        assertEquals(HttpStatus.SC_UNAUTHORIZED, response.getStatusCode());
        assertEquals(OAuth2Error.INVALID_CLIENT.getCode(), errorResponse.getCode());
        assertEquals("Client authentication failed", errorResponse.getDescription());
    }

    @Test
    void shouldReturn401WhenJwtMissingFromRequestProvided() throws Exception {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        String tokenRequestBody =
                "code=12345&redirect_uri=http://test.com&grant_type=authorization_code&client_id=test_client_id";
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
        assertEquals("Client authentication failed", errorResponse.getDescription());
    }

    @Test
    void shouldReturn400WhenAuthCodeIsUsedMoreThanOnce() throws Exception {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        String tokenRequestBody =
                "code="
                        + TEST_AUTHORIZATION_CODE
                        + "&redirect_uri=http://test.com&grant_type=authorization_code&client_id=test_client_id";
        event.setBody(tokenRequestBody);

        when(mockAccessTokenService.validateAuthorizationGrant(any()))
                .thenReturn(ValidationResult.createValidResult());
        mockSessionItem.setAccessToken(TEST_ACCESS_TOKEN);
        when(mockSessionService.getIpvSessionByAuthorizationCode(TEST_AUTHORIZATION_CODE))
                .thenReturn(mockSessionItem);
        when(mockClientOAuthSessionService.getClientOAuthSession(any()))
                .thenReturn(getClientOAuthSessionItem());

        APIGatewayProxyResponseEvent response = handler.handleRequest(event, context);

        verify(mockSessionService).revokeAccessToken(mockSessionItem);

        ErrorObject errorResponse = createErrorObjectFromResponse(response.getBody());
        assertEquals(HTTPResponse.SC_BAD_REQUEST, response.getStatusCode());
        assertEquals(OAuth2Error.INVALID_GRANT.getCode(), errorResponse.getCode());
        assertEquals("Authorization code used too many times", errorResponse.getDescription());
    }

    @Test
    void shouldReturn400WhenRevokingAccessTokenFails() throws Exception {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        String tokenRequestBody =
                "code="
                        + TEST_AUTHORIZATION_CODE
                        + "&redirect_uri=http://example.com&grant_type=authorization_code&client_id=test_client_id";
        event.setBody(tokenRequestBody);

        when(mockAccessTokenService.validateAuthorizationGrant(any()))
                .thenReturn(ValidationResult.createValidResult());
        mockSessionItem.setAccessToken(TEST_ACCESS_TOKEN);
        when(mockSessionService.getIpvSessionByAuthorizationCode(TEST_AUTHORIZATION_CODE))
                .thenReturn(mockSessionItem);
        when(mockClientOAuthSessionService.getClientOAuthSession(any()))
                .thenReturn(getClientOAuthSessionItem());

        String errorMessage = "Failed to revoke access token";
        doThrow(new IllegalArgumentException(errorMessage))
                .when(mockSessionService)
                .revokeAccessToken(mockSessionItem);

        APIGatewayProxyResponseEvent response = handler.handleRequest(event, context);

        ErrorObject errorResponse = createErrorObjectFromResponse(response.getBody());
        assertEquals(HTTPResponse.SC_BAD_REQUEST, response.getStatusCode());
        assertEquals(OAuth2Error.INVALID_GRANT.getCode(), errorResponse.getCode());
        assertEquals(errorMessage, errorResponse.getDescription());
    }

    @Test
    void shouldReturn400WhenRedirectURLsDoNotMatch() throws Exception {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        String tokenRequestBody =
                "redirect_uri=https://different.example.com&code="
                        + TEST_AUTHORIZATION_CODE
                        + "&client_assertion=eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0IiwiYXVkIjoiYWRtaW4iLCJpc3MiOiJtYXNvbi5tZXRhbXVnLm5ldCIsImV4cCI6MTU3NDUxMjc2NSwiaWF0IjoxNTY2NzM2NzY1LCJqdGkiOiJmN2JmZTMzZi03YmY3LTRlYjQtOGU1OS05OTE3OTliNWViOGEifQ==.EVcCaSqrSNVs3cWdLt-qkoqUk7rPHEOsDHS8yejwxMw&grant_type=authorization_code&client_id=test_client_id"; // pragma: allowlist secret
        event.setBody(tokenRequestBody);

        when(mockSessionService.getIpvSessionByAuthorizationCode(TEST_AUTHORIZATION_CODE))
                .thenReturn(mockSessionItem);
        when(mockAccessTokenService.validateAuthorizationGrant(any()))
                .thenReturn(ValidationResult.createValidResult());
        when(mockClientOAuthSessionService.getClientOAuthSession(any()))
                .thenReturn(getClientOAuthSessionItem());

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
        httpErrorResponse.setBody(responseBody);
        return ErrorObject.parse(httpErrorResponse);
    }

    private ClientOAuthSessionItem getClientOAuthSessionItem() {
        return ClientOAuthSessionItem.builder()
                .clientOAuthSessionId(SecureTokenHelper.getInstance().generate())
                .responseType("code")
                .state("test-state")
                .redirectUri("https://example.com/redirect")
                .govukSigninJourneyId("test-journey-id")
                .userId("test-user-id")
                .build();
    }
}
