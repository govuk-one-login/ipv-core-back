package uk.gov.di.ipv.core.processcricallback.service;

import com.github.tomakehurst.wiremock.junit5.WireMockRuntimeInfo;
import com.github.tomakehurst.wiremock.junit5.WireMockTest;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.token.AccessTokenType;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.dto.CredentialIssuerConfig;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.processcricallback.dto.CriCallbackRequest;
import uk.gov.di.ipv.core.processcricallback.exception.CriApiException;

import java.net.URI;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.JWT_TTL_SECONDS;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.*;

@WireMockTest
@ExtendWith(MockitoExtension.class)
public class CriApiServiceTest {
    private static final String TEST_CRI_ID = "test_cri_id";
    private static final String TEST_API_KEY = "test_api_key";
    private static final String TEST_AUTHORISATION_CODE = "test_authorisation_code";
    private static final String TEST_ACCESS_TOKEN = "d09rUXQZ-4AjT6DNsRXj00KBt7Pqh8tFXBq8ul6KYQ4";
    @Mock private ConfigService mockConfigService;
    @InjectMocks private CriApiService criApiService;

    @BeforeEach
    void setUp(WireMockRuntimeInfo wmRuntimeInfo)
            throws InvalidKeySpecException, NoSuchAlgorithmException, JOSEException {
        ECDSASigner signer = new ECDSASigner(getPrivateKey());
        criApiService = new CriApiService(mockConfigService, signer);

        when(mockConfigService.getSsmParameter(JWT_TTL_SECONDS)).thenReturn("900");
        var criConfig = getStubCredentialIssuerConfig(wmRuntimeInfo);
        when(mockConfigService.getCriConfig(any())).thenReturn(criConfig);
    }

    @Test
    void fetchAccessTokenShouldReturnAccessTokenForValidTokenResponse() throws CriApiException {
        var callbackRequest =
                CriCallbackRequest.builder()
                        .credentialIssuerId(TEST_CRI_ID)
                        .authorizationCode(TEST_AUTHORISATION_CODE)
                        .build();
        when(mockConfigService.getCriPrivateApiKey(any())).thenReturn(TEST_API_KEY);

        stubFor(
                post("/token")
                        .willReturn(
                                aResponse()
                                        .withHeader(
                                                "Content-Type", "application/json;charset=utf-8")
                                        .withBody(
                                                String.format(
                                                        "{\"access_token\":\"%s\",\"token_type\":\"Bearer\",\"expires_in\":3600}\n",
                                                        TEST_ACCESS_TOKEN))));

        var accessToken = criApiService.fetchAccessToken(callbackRequest, null);

        AccessTokenType type = accessToken.getType();
        assertEquals(AccessTokenType.BEARER, type);
        assertEquals(3600, accessToken.getLifetime());
        assertEquals(TEST_ACCESS_TOKEN, accessToken.getValue());
    }

    @Test
    void fetchAccessTokenShouldReturnAccessTokenForNoApiKey() throws CriApiException {
        var callbackRequest =
                CriCallbackRequest.builder()
                        .credentialIssuerId(TEST_CRI_ID)
                        .authorizationCode(TEST_AUTHORISATION_CODE)
                        .build();
        // getCriPrivateApiKey not mocked

        stubFor(
                post("/token")
                        .willReturn(
                                aResponse()
                                        .withHeader(
                                                "Content-Type", "application/json;charset=utf-8")
                                        .withBody(
                                                String.format(
                                                        "{\"access_token\":\"%s\",\"token_type\":\"Bearer\",\"expires_in\":3600}\n",
                                                        TEST_ACCESS_TOKEN))));

        var accessToken = criApiService.fetchAccessToken(callbackRequest, null);

        AccessTokenType type = accessToken.getType();
        assertEquals(AccessTokenType.BEARER, type);
        assertEquals(3600, accessToken.getLifetime());
        assertEquals(TEST_ACCESS_TOKEN, accessToken.getValue());
    }

    @Test
    void fetchAccessTokenThrowsCriApiExceptionForErrorTokenResponse() {
        var callbackRequest =
                CriCallbackRequest.builder()
                        .credentialIssuerId(TEST_CRI_ID)
                        .authorizationCode(TEST_AUTHORISATION_CODE)
                        .build();
        when(mockConfigService.getCriPrivateApiKey(any())).thenReturn(TEST_API_KEY);

        stubFor(
                post("/token")
                        .willReturn(
                                aResponse()
                                        .withStatus(400)
                                        .withHeader(
                                                "Content-Type", "application/json;charset=utf-8")
                                        .withBody(
                                                "{ \"error\": \"invalid_request\", \"error_description\": \"Request was missing the 'redirect_uri' parameter.\", \"error_uri\": \"See the full API docs at https://authorization-server.com/docs/access_token\"}")));

        CriApiException exception =
                assertThrows(
                        CriApiException.class,
                        () -> criApiService.fetchAccessToken(callbackRequest, null));

        assertEquals(HTTPResponse.SC_BAD_REQUEST, exception.getHttpStatusCode());
        assertEquals(ErrorResponse.INVALID_TOKEN_REQUEST, exception.getErrorResponse());
    }

    @Test
    void fetchAccessTokenThrowsCriApiExceptionForInvalidHeaderResponse() {
        var callbackRequest =
                CriCallbackRequest.builder()
                        .credentialIssuerId(TEST_CRI_ID)
                        .authorizationCode(TEST_AUTHORISATION_CODE)
                        .build();
        when(mockConfigService.getCriPrivateApiKey(any())).thenReturn(TEST_API_KEY);

        stubFor(
                post("/token")
                        .willReturn(
                                aResponse()
                                        .withHeader("Content-Type", "application/xml;charset=utf-8")
                                        .withBody(
                                                "{\"access_token\":\"d09rUXQZ-4AjT6DNsRXj00KBt7Pqh8tFXBq8ul6KYQ4\",\"token_type\":\"Bearer\",\"expires_in\":3600}\n")));

        CriApiException exception =
                assertThrows(
                        CriApiException.class,
                        () -> criApiService.fetchAccessToken(callbackRequest, null));

        assertEquals(HTTPResponse.SC_SERVER_ERROR, exception.getHttpStatusCode());
        assertEquals(
                ErrorResponse.FAILED_TO_EXCHANGE_AUTHORIZATION_CODE, exception.getErrorResponse());
    }

    // fetchAccessToken tests should also validate the http request made is the right shape
    // Might even need to split method into building http request and dealing with result after
    // sending

    @Test
    void fetchVerifiableCredential() throws CriApiException {
        var callbackRequest = CriCallbackRequest.builder().credentialIssuerId(TEST_CRI_ID).build();
        when(mockConfigService.getCriPrivateApiKey(any())).thenReturn(TEST_API_KEY);

        stubFor(
                post("/credentials/issue")
                        .willReturn(
                                aResponse()
                                        .withHeader("Content-Type", "application/xml;charset=utf-8")
                                        .withBody(
                                                "{\"access_token\":\"d09rUXQZ-4AjT6DNsRXj00KBt7Pqh8tFXBq8ul6KYQ4\",\"token_type\":\"Bearer\",\"expires_in\":3600}\n")));

        criApiService.fetchVerifiableCredential(
                new BearerAccessToken(TEST_ACCESS_TOKEN), callbackRequest, null);
    }

    @Test
    void fetchVerifiableCredentialWithoutApiKey() throws CriApiException {
        var callbackRequest = CriCallbackRequest.builder().credentialIssuerId(TEST_CRI_ID).build();

        criApiService.fetchVerifiableCredential(
                new BearerAccessToken(TEST_ACCESS_TOKEN), callbackRequest, null);
    }

    private CredentialIssuerConfig getStubCredentialIssuerConfig(
            WireMockRuntimeInfo wmRuntimeInfo) {
        return new CredentialIssuerConfig(
                URI.create("http://localhost:" + wmRuntimeInfo.getHttpPort() + "/token"),
                URI.create(
                        "http://localhost:"
                                + wmRuntimeInfo.getHttpPort()
                                + "/credentials/issue"), // is this right?
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
