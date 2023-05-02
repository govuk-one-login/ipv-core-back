package uk.gov.di.ipv.core.retrievecrioauthaccesstoken.service;

import com.github.tomakehurst.wiremock.junit5.WireMockRuntimeInfo;
import com.github.tomakehurst.wiremock.junit5.WireMockTest;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.AccessTokenType;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.dto.CredentialIssuerConfig;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.retrievecrioauthaccesstoken.exception.AuthCodeToAccessTokenException;

import java.net.URI;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.stubFor;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.JWT_TTL_SECONDS;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.EC_PRIVATE_KEY;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.EC_PUBLIC_JWK;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.RSA_ENCRYPTION_PUBLIC_JWK;

@WireMockTest
@ExtendWith(MockitoExtension.class)
class AuthCodeToAccessTokenServiceTest {
    private static final String TEST_AUTH_CODE = "test-auth-code";

    @Mock private ConfigService mockConfigService;

    private AuthCodeToAccessTokenService authCodeToAccessTokenService;
    private final String testApiKey = "test-api-key";
    private final String cri = "ukPassport";

    @BeforeEach
    void setUp() throws InvalidKeySpecException, NoSuchAlgorithmException, JOSEException {
        ECDSASigner signer = new ECDSASigner(getPrivateKey());
        authCodeToAccessTokenService = new AuthCodeToAccessTokenService(mockConfigService, signer);
    }

    @Test
    void validTokenResponse(WireMockRuntimeInfo wmRuntimeInfo) {
        when(mockConfigService.getSsmParameter(JWT_TTL_SECONDS)).thenReturn("900");
        stubFor(
                post("/token")
                        .willReturn(
                                aResponse()
                                        .withHeader(
                                                "Content-Type", "application/json;charset=utf-8")
                                        .withBody(
                                                "{\"access_token\":\"d09rUXQZ-4AjT6DNsRXj00KBt7Pqh8tFXBq8ul6KYQ4\",\"token_type\":\"Bearer\",\"expires_in\":3600}\n")));

        CredentialIssuerConfig credentialIssuerConfig =
                getStubCredentialIssuerConfig(wmRuntimeInfo);

        AccessToken accessToken =
                authCodeToAccessTokenService.exchangeCodeForToken(
                        TEST_AUTH_CODE, credentialIssuerConfig, testApiKey, cri);
        AccessTokenType type = accessToken.getType();
        assertEquals("Bearer", type.toString());
        assertEquals(3600, accessToken.getLifetime());
        assertEquals("d09rUXQZ-4AjT6DNsRXj00KBt7Pqh8tFXBq8ul6KYQ4", accessToken.getValue());
    }

    @Test
    void validTokenResponseForAppJourney(WireMockRuntimeInfo wmRuntimeInfo) {
        when(mockConfigService.getSsmParameter(JWT_TTL_SECONDS)).thenReturn("900");
        stubFor(
                post("/token")
                        .willReturn(
                                aResponse()
                                        .withHeader(
                                                "Content-Type", "application/json;charset=utf-8")
                                        .withBody(
                                                "{\"access_token\":\"d09rUXQZ-4AjT6DNsRXj00KBt7Pqh8tFXBq8ul6KYQ4\",\"token_type\":\"Bearer\",\"expires_in\":3600}\n")));

        CredentialIssuerConfig credentialIssuerConfig =
                getStubCredentialIssuerConfig(wmRuntimeInfo);

        AccessToken accessToken =
                authCodeToAccessTokenService.exchangeCodeForToken(
                        TEST_AUTH_CODE, credentialIssuerConfig, testApiKey, cri);
        AccessTokenType type = accessToken.getType();
        assertEquals("Bearer", type.toString());
        assertEquals(3600, accessToken.getLifetime());
        assertEquals("d09rUXQZ-4AjT6DNsRXj00KBt7Pqh8tFXBq8ul6KYQ4", accessToken.getValue());
    }

    @Test
    void validTokenResponseWithoutApiKey(WireMockRuntimeInfo wmRuntimeInfo) {
        when(mockConfigService.getSsmParameter(JWT_TTL_SECONDS)).thenReturn("900");
        stubFor(
                post("/token")
                        .willReturn(
                                aResponse()
                                        .withHeader(
                                                "Content-Type", "application/json;charset=utf-8")
                                        .withBody(
                                                "{\"access_token\":\"d09rUXQZ-4AjT6DNsRXj00KBt7Pqh8tFXBq8ul6KYQ4\",\"token_type\":\"Bearer\",\"expires_in\":3600}\n")));

        CredentialIssuerConfig credentialIssuerConfig =
                getStubCredentialIssuerConfig(wmRuntimeInfo);

        AccessToken accessToken =
                authCodeToAccessTokenService.exchangeCodeForToken(
                        TEST_AUTH_CODE, credentialIssuerConfig, null, cri);
        AccessTokenType type = accessToken.getType();
        assertEquals("Bearer", type.toString());
        assertEquals(3600, accessToken.getLifetime());
        assertEquals("d09rUXQZ-4AjT6DNsRXj00KBt7Pqh8tFXBq8ul6KYQ4", accessToken.getValue());
    }

    @Test
    void tokenErrorResponse(WireMockRuntimeInfo wmRuntimeInfo) {
        when(mockConfigService.getSsmParameter(JWT_TTL_SECONDS)).thenReturn("900");
        var errorJson =
                "{ \"error\": \"invalid_request\", \"error_description\": \"Request was missing the 'redirect_uri' parameter.\", \"error_uri\": \"See the full API docs at https://authorization-server.com/docs/access_token\"}";
        stubFor(
                post("/token")
                        .willReturn(
                                aResponse()
                                        .withStatus(400)
                                        .withHeader(
                                                "Content-Type", "application/json;charset=utf-8")
                                        .withBody(errorJson)));

        CredentialIssuerConfig credentialIssuerConfig =
                getStubCredentialIssuerConfig(wmRuntimeInfo);

        AuthCodeToAccessTokenException exception =
                assertThrows(
                        AuthCodeToAccessTokenException.class,
                        () ->
                                authCodeToAccessTokenService.exchangeCodeForToken(
                                        TEST_AUTH_CODE, credentialIssuerConfig, testApiKey, cri));

        assertEquals(HTTPResponse.SC_BAD_REQUEST, exception.getHttpStatusCode());
        assertEquals(ErrorResponse.INVALID_TOKEN_REQUEST, exception.getErrorResponse());
    }

    @Test
    void invalidHeaderThrowsCredentialIssuerException(WireMockRuntimeInfo wmRuntimeInfo) {
        when(mockConfigService.getSsmParameter(JWT_TTL_SECONDS)).thenReturn("900");
        stubFor(
                post("/token")
                        .willReturn(
                                aResponse()
                                        .withHeader("Content-Type", "application/xml;charset=utf-8")
                                        .withBody(
                                                "{\"access_token\":\"d09rUXQZ-4AjT6DNsRXj00KBt7Pqh8tFXBq8ul6KYQ4\",\"token_type\":\"Bearer\",\"expires_in\":3600}\n")));

        CredentialIssuerConfig credentialIssuerConfig =
                getStubCredentialIssuerConfig(wmRuntimeInfo);
        AuthCodeToAccessTokenException exception =
                assertThrows(
                        AuthCodeToAccessTokenException.class,
                        () ->
                                authCodeToAccessTokenService.exchangeCodeForToken(
                                        TEST_AUTH_CODE, credentialIssuerConfig, testApiKey, cri));

        assertEquals(HTTPResponse.SC_SERVER_ERROR, exception.getHttpStatusCode());
        assertEquals(
                ErrorResponse.FAILED_TO_EXCHANGE_AUTHORIZATION_CODE, exception.getErrorResponse());
    }

    private CredentialIssuerConfig getStubCredentialIssuerConfig(
            WireMockRuntimeInfo wmRuntimeInfo) {
        return new CredentialIssuerConfig(
                URI.create("http://localhost:" + wmRuntimeInfo.getHttpPort() + "/token"),
                URI.create(
                        "http://localhost:" + wmRuntimeInfo.getHttpPort() + "/credentials/issue"),
                URI.create("http://localhost:" + wmRuntimeInfo.getHttpPort() + "/authorizeUrl"),
                "ipv-core",
                EC_PUBLIC_JWK,
                RSA_ENCRYPTION_PUBLIC_JWK,
                "test-audience",
                URI.create(
                        "http://localhost:"
                                + wmRuntimeInfo.getHttpPort()
                                + "/credential-issuer/callback?id=StubPassport"),
                true);
    }

    private ECPrivateKey getPrivateKey() throws InvalidKeySpecException, NoSuchAlgorithmException {
        return (ECPrivateKey)
                KeyFactory.getInstance("EC")
                        .generatePrivate(
                                new PKCS8EncodedKeySpec(
                                        Base64.getDecoder().decode(EC_PRIVATE_KEY)));
    }
}
