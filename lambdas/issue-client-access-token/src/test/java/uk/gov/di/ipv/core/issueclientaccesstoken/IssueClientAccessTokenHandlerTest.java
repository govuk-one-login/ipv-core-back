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
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import software.amazon.awssdk.http.HttpStatusCode;
import uk.gov.di.ipv.core.issueclientaccesstoken.exception.ClientAuthenticationException;
import uk.gov.di.ipv.core.issueclientaccesstoken.service.AccessTokenService;
import uk.gov.di.ipv.core.issueclientaccesstoken.validation.TokenRequestValidator;
import uk.gov.di.ipv.core.library.config.domain.Config;
import uk.gov.di.ipv.core.library.dto.AuthorizationCodeMetadata;
import uk.gov.di.ipv.core.library.exceptions.IpvSessionNotFoundException;
import uk.gov.di.ipv.core.library.helpers.SecureTokenHelper;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.ClientOAuthSessionDetailsService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.testhelpers.unit.ConfigServiceHelper;
import uk.gov.di.ipv.core.library.testhelpers.unit.LogCollector;
import uk.gov.di.ipv.core.library.validation.ValidationResult;

import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.StringContains.containsString;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class IssueClientAccessTokenHandlerTest {
    private final String TEST_AUTHORIZATION_CODE = "12345";
    private final String TEST_ACCESS_TOKEN = "98765";
    private final String TEST_REDIRECT_URL = "https://callback.example.com";
    private final String TEST_SESSION_ID = "test-session-id";
    private final ObjectMapper objectMapper = new ObjectMapper();
    private IpvSessionItem sessionItem;
    @Mock private Context mockContext;
    @Mock private ConfigService mockConfigService;
    @Mock private Config mockConfig;
    @Mock private AccessTokenService mockAccessTokenService;
    @Mock private IpvSessionService mockSessionService;
    @Mock private ClientOAuthSessionDetailsService mockClientOAuthSessionService;
    @Mock private TokenRequestValidator mockTokenRequestValidator;

    private IssueClientAccessTokenHandler handler;
    private TokenResponse tokenResponse;

    @BeforeEach
    void setUp() {
        ConfigServiceHelper.stubDefaultComponentIdConfig(mockConfigService, mockConfig);
        AccessToken accessToken = new BearerAccessToken();
        tokenResponse = new AccessTokenResponse(new Tokens(accessToken, null));

        lenient().when(mockAccessTokenService.generateAccessToken()).thenReturn(tokenResponse);
        lenient().when(mockConfigService.getAuthCodeExpirySeconds()).thenReturn(3600L);

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

        sessionItem = new IpvSessionItem();
        sessionItem.setIpvSessionId(TEST_SESSION_ID);
        sessionItem.setAuthorizationCode(TEST_AUTHORIZATION_CODE);
        sessionItem.setAuthorizationCodeMetadata(mockAuthorizationCodeMetadata);
        sessionItem.setFeatureSet("someCoolNewThing");
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
                .thenReturn(sessionItem);
        when(mockClientOAuthSessionService.getClientOAuthSession(any()))
                .thenReturn(getClientOAuthSessionItem());
        when(mockClientOAuthSessionService.getClientOAuthSession(any()))
                .thenReturn(getClientOAuthSessionItem());

        APIGatewayProxyResponseEvent response = handler.handleRequest(event, mockContext);

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

        APIGatewayProxyResponseEvent response = handler.handleRequest(event, mockContext);

        ErrorObject errorResponse = createErrorObjectFromResponse(response.getBody());
        assertEquals(HttpStatusCode.BAD_REQUEST, response.getStatusCode());
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

        APIGatewayProxyResponseEvent response = handler.handleRequest(event, mockContext);

        ErrorObject errorResponse = createErrorObjectFromResponse(response.getBody());
        assertEquals(HttpStatusCode.BAD_REQUEST, response.getStatusCode());
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

        APIGatewayProxyResponseEvent response = handler.handleRequest(event, mockContext);

        ErrorObject errorResponse = createErrorObjectFromResponse(response.getBody());
        assertEquals(HttpStatusCode.BAD_REQUEST, response.getStatusCode());
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

        APIGatewayProxyResponseEvent response = handler.handleRequest(event, mockContext);

        ErrorObject errorResponse = createErrorObjectFromResponse(response.getBody());
        assertEquals(HttpStatusCode.BAD_REQUEST, response.getStatusCode());
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

        APIGatewayProxyResponseEvent response = handler.handleRequest(event, mockContext);

        ErrorObject errorResponse = createErrorObjectFromResponse(response.getBody());
        assertEquals(HttpStatusCode.BAD_REQUEST, response.getStatusCode());
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

        when(mockConfigService.getAuthCodeExpirySeconds()).thenReturn(0L);
        when(mockAccessTokenService.validateAuthorizationGrant(any()))
                .thenReturn(ValidationResult.createValidResult());
        when(mockSessionService.getIpvSessionByAuthorizationCode(TEST_AUTHORIZATION_CODE))
                .thenReturn(sessionItem);
        when(mockClientOAuthSessionService.getClientOAuthSession(any()))
                .thenReturn(getClientOAuthSessionItem());

        APIGatewayProxyResponseEvent response = handler.handleRequest(event, mockContext);

        ErrorObject errorResponse = createErrorObjectFromResponse(response.getBody());
        assertEquals(HttpStatusCode.BAD_REQUEST, response.getStatusCode());
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

        doThrow(new ClientAuthenticationException("error"))
                .when(mockTokenRequestValidator)
                .authenticateClient(any());

        APIGatewayProxyResponseEvent response = handler.handleRequest(event, mockContext);

        ErrorObject errorResponse = createErrorObjectFromResponse(response.getBody());
        assertEquals(HttpStatusCode.UNAUTHORIZED, response.getStatusCode());
        assertEquals(OAuth2Error.INVALID_CLIENT.getCode(), errorResponse.getCode());
        assertEquals("Client authentication failed", errorResponse.getDescription());
    }

    @Test
    void shouldReturn401WhenJwtMissingFromRequestProvided() throws Exception {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        String tokenRequestBody =
                "code=12345&redirect_uri=http://test.com&grant_type=authorization_code&client_id=test_client_id";
        event.setBody(tokenRequestBody);

        doThrow(new ClientAuthenticationException("error"))
                .when(mockTokenRequestValidator)
                .authenticateClient(any());

        APIGatewayProxyResponseEvent response = handler.handleRequest(event, mockContext);

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
        sessionItem.setAccessToken(TEST_ACCESS_TOKEN);
        when(mockSessionService.getIpvSessionByAuthorizationCode(TEST_AUTHORIZATION_CODE))
                .thenReturn(sessionItem);
        when(mockClientOAuthSessionService.getClientOAuthSession(any()))
                .thenReturn(getClientOAuthSessionItem());

        APIGatewayProxyResponseEvent response = handler.handleRequest(event, mockContext);

        verify(mockSessionService).revokeAccessToken(sessionItem);

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
        sessionItem.setAccessToken(TEST_ACCESS_TOKEN);
        when(mockSessionService.getIpvSessionByAuthorizationCode(TEST_AUTHORIZATION_CODE))
                .thenReturn(sessionItem);
        when(mockClientOAuthSessionService.getClientOAuthSession(any()))
                .thenReturn(getClientOAuthSessionItem());

        String errorMessage = "Failed to revoke access token";
        doThrow(new IllegalArgumentException(errorMessage))
                .when(mockSessionService)
                .revokeAccessToken(sessionItem);

        APIGatewayProxyResponseEvent response = handler.handleRequest(event, mockContext);

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
                .thenReturn(sessionItem);
        when(mockAccessTokenService.validateAuthorizationGrant(any()))
                .thenReturn(ValidationResult.createValidResult());
        when(mockClientOAuthSessionService.getClientOAuthSession(any()))
                .thenReturn(getClientOAuthSessionItem());

        APIGatewayProxyResponseEvent response = handler.handleRequest(event, mockContext);

        ErrorObject errorResponse = createErrorObjectFromResponse(response.getBody());
        assertEquals(HTTPResponse.SC_BAD_REQUEST, response.getStatusCode());
        assertEquals(OAuth2Error.INVALID_GRANT.getCode(), errorResponse.getCode());
        assertEquals(
                "Redirect URL in token request does not match redirect URL received in auth code request",
                errorResponse.getDescription());
    }

    @Test
    void shouldLogRuntimeExceptionsAndRethrow() throws Exception {
        // Arrange
        doThrow(new RuntimeException("Test error"))
                .when(mockTokenRequestValidator)
                .authenticateClient(any());
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();

        var logCollector = LogCollector.getLogCollectorFor(IssueClientAccessTokenHandler.class);

        // Act
        var thrown =
                assertThrows(
                        Exception.class,
                        () -> handler.handleRequest(event, mockContext),
                        "Expected handleRequest() to throw, but it didn't");

        // Assert
        assertEquals("Test error", thrown.getMessage());
        var logMessage = logCollector.getLogMessages().get(0);
        assertThat(logMessage, containsString("Unhandled lambda exception"));
        assertThat(logMessage, containsString("Test error"));
    }

    private ErrorObject createErrorObjectFromResponse(String responseBody) throws ParseException {
        HTTPResponse httpErrorResponse = new HTTPResponse(HttpStatusCode.BAD_REQUEST);
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
