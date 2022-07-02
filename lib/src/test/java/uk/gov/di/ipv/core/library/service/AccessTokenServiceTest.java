package uk.gov.di.ipv.core.library.service;

import com.nimbusds.oauth2.sdk.AccessTokenResponse;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.RefreshTokenGrant;
import com.nimbusds.oauth2.sdk.Scope;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import com.nimbusds.oauth2.sdk.token.Tokens;
import org.apache.commons.codec.digest.DigestUtils;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.helpers.SecureTokenHelper;
import uk.gov.di.ipv.core.library.persistence.DataStore;
import uk.gov.di.ipv.core.library.persistence.item.AccessTokenItem;
import uk.gov.di.ipv.core.library.validation.ValidationResult;

import java.net.URI;
import java.time.Instant;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AccessTokenServiceTest {

    @Mock private DataStore<AccessTokenItem> mockDataStore;
    @Mock private ConfigurationService mockConfigurationService;

    private AccessTokenService accessTokenService;

    @BeforeEach
    void setUp() {
        this.accessTokenService = new AccessTokenService(mockDataStore, mockConfigurationService);
    }

    @Test
    void shouldReturnSuccessfulTokenResponseOnSuccessfulExchange() {
        long testTokenTtl = 2400L;
        Scope testScope = new Scope("test-scope");
        when(mockConfigurationService.getBearerAccessTokenTtl()).thenReturn(testTokenTtl);

        TokenResponse response = accessTokenService.generateAccessToken(testScope);

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
        ValidationResult<ErrorObject> validationResult =
                accessTokenService.validateAuthorizationGrant(
                        new RefreshTokenGrant(new RefreshToken()));

        assertNotNull(validationResult);
        assertFalse(validationResult.isValid());
        assertEquals(OAuth2Error.UNSUPPORTED_GRANT_TYPE, validationResult.getError());
    }

    @Test
    void shouldNotReturnValidationErrorWhenAValidAuthGrantIsProvided() {
        ValidationResult<ErrorObject> validationResult =
                accessTokenService.validateAuthorizationGrant(
                        new AuthorizationCodeGrant(
                                new AuthorizationCode(), URI.create("https://test.com")));

        assertNotNull(validationResult);
        assertTrue(validationResult.isValid());
        assertNull(validationResult.getError());
    }

    @Test
    void validateScopeShouldReturnValidationErrorForMissingScope() {
        ValidationResult<ErrorObject> scopeValidationResult =
                accessTokenService.validateScope(new Scope());

        assertFalse(scopeValidationResult.isValid());
        assertEquals(OAuth2Error.INVALID_SCOPE, scopeValidationResult.getError());
    }

    @Test
    void validateScopeShouldValidResponseForWhenScopePresent() {
        ValidationResult<ErrorObject> scopeValidationResult =
                accessTokenService.validateScope(new Scope("some-scope"));

        assertTrue(scopeValidationResult.isValid());
        assertNull(scopeValidationResult.getError());
    }

    @Test
    void shouldPersistAccessToken() {
        String testIpvSessionId = SecureTokenHelper.generate();
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
                DigestUtils.sha256Hex(
                        accessTokenResponse.getTokens().getBearerAccessToken().getValue()),
                capturedAccessTokenItem.getAccessToken());
    }

    @Test
    void shouldGetAccessTokenItemWhenValidAccessTokenProvided() {
        String testIpvSessionId = SecureTokenHelper.generate();
        String accessToken = new BearerAccessToken().getValue();

        AccessTokenItem expectedAccessTokenItem = new AccessTokenItem();
        expectedAccessTokenItem.setIpvSessionId(testIpvSessionId);
        when(mockDataStore.getItem(DigestUtils.sha256Hex(accessToken)))
                .thenReturn(expectedAccessTokenItem);

        AccessTokenItem actualAccessTokenItem = accessTokenService.getAccessToken(accessToken);

        verify(mockDataStore).getItem(DigestUtils.sha256Hex(accessToken));

        assertNotNull(actualAccessTokenItem);
        assertEquals(expectedAccessTokenItem, actualAccessTokenItem);
    }

    @Test
    void shouldReturnNullWhenInvalidAccessTokenProvided() {
        String accessToken = new BearerAccessToken().getValue();

        when(mockDataStore.getItem(DigestUtils.sha256Hex(accessToken))).thenReturn(null);

        AccessTokenItem actualAccessTokenItem = accessTokenService.getAccessToken(accessToken);

        verify(mockDataStore).getItem(DigestUtils.sha256Hex(accessToken));
        assertNull(actualAccessTokenItem);
    }

    @Test
    void shouldRevokeAccessToken() {
        String accessToken = "test-access-token";

        AccessTokenItem accessTokenItem = new AccessTokenItem();
        accessTokenItem.setAccessToken(accessToken);

        when(mockDataStore.getItem(accessToken)).thenReturn(accessTokenItem);

        accessTokenService.revokeAccessToken(accessToken);

        ArgumentCaptor<AccessTokenItem> accessTokenItemArgCaptor =
                ArgumentCaptor.forClass(AccessTokenItem.class);

        verify(mockDataStore).update(accessTokenItemArgCaptor.capture());
        assertNotNull(accessTokenItemArgCaptor.getValue().getRevokedAtDateTime());
    }

    @Test
    void shouldNotAttemptUpdateIfAccessTokenIsAlreadyRevoked() {
        String accessToken = "test-access-token";

        AccessTokenItem accessTokenItem = new AccessTokenItem();
        accessTokenItem.setAccessToken(accessToken);
        accessTokenItem.setRevokedAtDateTime(Instant.now().toString());

        when(mockDataStore.getItem(accessToken)).thenReturn(accessTokenItem);

        accessTokenService.revokeAccessToken(accessToken);

        verify(mockDataStore, Mockito.times(0)).update(any());
    }

    @Test
    void shouldThrowExceptionIfAccessTokenCanNotBeFoundWhenRevoking() {
        String accessToken = "test-access-token";

        when(mockDataStore.getItem(accessToken)).thenReturn(null);

        IllegalArgumentException thrown =
                assertThrows(
                        IllegalArgumentException.class,
                        () -> accessTokenService.revokeAccessToken(accessToken));
        assertEquals(
                "Failed to revoke access token - access token could not be found in DynamoDB",
                thrown.getMessage());
    }
}
