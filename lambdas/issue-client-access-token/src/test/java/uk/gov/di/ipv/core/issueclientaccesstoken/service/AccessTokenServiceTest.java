package uk.gov.di.ipv.core.issueclientaccesstoken.service;

import com.nimbusds.oauth2.sdk.AccessTokenResponse;
import com.nimbusds.oauth2.sdk.AuthorizationCode;
import com.nimbusds.oauth2.sdk.AuthorizationCodeGrant;
import com.nimbusds.oauth2.sdk.ErrorObject;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.RefreshTokenGrant;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.validation.ValidationResult;

import java.net.URI;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.issueclientaccesstoken.service.AccessTokenService.DEFAULT_SCOPE;

@ExtendWith(MockitoExtension.class)
class AccessTokenServiceTest {
    @Mock private ConfigService mockConfigService;

    private AccessTokenService accessTokenService;

    @BeforeEach
    void setUp() {
        this.accessTokenService = new AccessTokenService(mockConfigService);
    }

    @Test
    void shouldReturnSuccessfulTokenResponseOnSuccessfulExchange() {
        long testTokenTtl = 2400L;
        when(mockConfigService.getBearerAccessTokenTtl()).thenReturn(testTokenTtl);

        TokenResponse response = accessTokenService.generateAccessToken();

        assertInstanceOf(AccessTokenResponse.class, response);
        assertNotNull(response.toSuccessResponse().getTokens().getAccessToken().getValue());
        assertEquals(
                testTokenTtl,
                response.toSuccessResponse().getTokens().getBearerAccessToken().getLifetime());
        assertEquals(
                DEFAULT_SCOPE,
                response.toSuccessResponse().getTokens().getAccessToken().getScope());
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
}
