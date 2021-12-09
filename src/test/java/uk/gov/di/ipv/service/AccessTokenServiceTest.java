package uk.gov.di.ipv.service;

import com.nimbusds.oauth2.sdk.AccessTokenResponse;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.RefreshTokenGrant;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.oauth2.sdk.token.Tokens;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import uk.gov.di.ipv.persistence.DataStore;
import uk.gov.di.ipv.persistence.item.AccessTokenItem;
import uk.gov.di.ipv.validation.ValidationResult;
import uk.org.webcompere.systemstubs.environment.EnvironmentVariables;
import uk.org.webcompere.systemstubs.jupiter.SystemStub;
import uk.org.webcompere.systemstubs.jupiter.SystemStubsExtension;
import uk.org.webcompere.systemstubs.properties.SystemProperties;

import java.net.URI;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.service.ConfigurationService.IS_LOCAL;

@ExtendWith(SystemStubsExtension.class)
class AccessTokenServiceTest {

    @SystemStub private EnvironmentVariables environmentVariables;

    @SystemStub private SystemProperties systemProperties;

    private DataStore<AccessTokenItem> mockDataStore;
    private ConfigurationService mockConfigurationService;
    private AccessTokenService accessTokenService;

    @BeforeEach
    void setUp() {
        this.mockConfigurationService = mock(ConfigurationService.class);
        this.mockDataStore = mock(DataStore.class);
        this.accessTokenService = new AccessTokenService(mockDataStore, mockConfigurationService);
    }

    @Test
    void noArgsConstructor() {
        environmentVariables.set(IS_LOCAL, "true");
        systemProperties.set(
                "software.amazon.awssdk.http.service.impl",
                "software.amazon.awssdk.http.urlconnection.UrlConnectionSdkHttpService");

        assertDoesNotThrow(() -> new AccessTokenService());
    }

    @Test
    void shouldReturnSuccessfulTokenResponseOnSuccessfulExchange() throws Exception {
        long testTokenTtl = 2400L;
        Scope testScope = new Scope("test-scope");
        TokenRequest tokenRequest =
                new TokenRequest(
                        null,
                        new ClientID("test-client-id"),
                        new AuthorizationCodeGrant(
                                new AuthorizationCode("123456"), new URI("http://test.com")),
                        testScope);
        when(mockConfigurationService.getBearerAccessTokenTtl()).thenReturn(testTokenTtl);

        TokenResponse response = accessTokenService.generateAccessToken(tokenRequest);

        assertInstanceOf(AccessTokenResponse.class, response);
        assertNotNull(response.toSuccessResponse().getTokens().getAccessToken().getValue());
        assertEquals(
                testTokenTtl,
                response.toSuccessResponse().getTokens().getBearerAccessToken().getLifetime());
        assertEquals(
                testScope,
                response.toSuccessResponse().getTokens().getBearerAccessToken().getScope());
    }

    @Test
    void shouldReturnValidationErrorWhenInvalidGrantTypeProvided() {
        TokenRequest tokenRequest =
                new TokenRequest(
                        null,
                        new ClientID("test-client-id"),
                        new RefreshTokenGrant(new RefreshToken()));

        ValidationResult<ErrorObject> validationResult =
                accessTokenService.validateTokenRequest(tokenRequest);

        assertNotNull(validationResult);
        assertFalse(validationResult.isValid());
        assertEquals(OAuth2Error.UNSUPPORTED_GRANT_TYPE, validationResult.getError());
    }

    @Test
    void shouldNotReturnValidationErrorWhenAValidTokenRequestIsProvided() {
        TokenRequest tokenRequest =
                new TokenRequest(
                        null,
                        new ClientID("test-client-id"),
                        new AuthorizationCodeGrant(
                                new AuthorizationCode(), URI.create("https://test.com")));

        ValidationResult<ErrorObject> validationResult =
                accessTokenService.validateTokenRequest(tokenRequest);

        assertNotNull(validationResult);
        assertTrue(validationResult.isValid());
        assertNull(validationResult.getError());
    }

    @Test
    void shouldPersistAccessToken() {
        String testIpvSessionId = UUID.randomUUID().toString();
        AccessToken accessToken = new BearerAccessToken();
        AccessTokenResponse accessTokenResponse =
                new AccessTokenResponse(new Tokens(accessToken, null));
        ArgumentCaptor<AccessTokenItem> accessTokenItemArgCaptor =
                ArgumentCaptor.forClass(AccessTokenItem.class);

        accessTokenService.persistAccessToken(accessTokenResponse, testIpvSessionId);

        verify(mockDataStore).create(accessTokenItemArgCaptor.capture());
        AccessTokenItem capturedAccessTokenItem = accessTokenItemArgCaptor.getValue();
        assertNotNull(capturedAccessTokenItem);
        assertEquals(testIpvSessionId, capturedAccessTokenItem.getIpvSessionId());
        assertEquals(
                accessTokenResponse.getTokens().getBearerAccessToken().toAuthorizationHeader(),
                capturedAccessTokenItem.getAccessToken());
    }

    @Test
    void shouldGetSessionIdByAccessTokenWhenValidAccessTokenProvided() {
        String testIpvSessionId = UUID.randomUUID().toString();
        String accessToken = new BearerAccessToken().toAuthorizationHeader();

        AccessTokenItem accessTokenItem = new AccessTokenItem();
        accessTokenItem.setIpvSessionId(testIpvSessionId);
        when(mockDataStore.getItem(accessToken)).thenReturn(accessTokenItem);

        String resultIpvSessionId = accessTokenService.getIpvSessionIdByAccessToken(accessToken);

        verify(mockDataStore).getItem(accessToken);

        assertNotNull(resultIpvSessionId);
        assertEquals(testIpvSessionId, resultIpvSessionId);
    }

    @Test
    void shouldReturnNullWhenInvalidAccessTokenProvided() {
        String accessToken = new BearerAccessToken().toAuthorizationHeader();

        when(mockDataStore.getItem(accessToken)).thenReturn(null);

        String resultIpvSessionId = accessTokenService.getIpvSessionIdByAccessToken(accessToken);

        verify(mockDataStore).getItem(accessToken);
        assertNull(resultIpvSessionId);
    }
}
