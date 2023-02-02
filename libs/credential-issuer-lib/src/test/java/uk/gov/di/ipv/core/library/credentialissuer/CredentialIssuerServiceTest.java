package uk.gov.di.ipv.core.library.credentialissuer;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.tomakehurst.wiremock.client.WireMock;
import com.github.tomakehurst.wiremock.junit5.WireMockRuntimeInfo;
import com.github.tomakehurst.wiremock.junit5.WireMockTest;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.token.AccessTokenType;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.ArgumentMatchers;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
import uk.gov.di.ipv.core.library.credentialissuer.exceptions.CredentialIssuerException;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.dto.CredentialIssuerConfig;
import uk.gov.di.ipv.core.library.dto.CredentialIssuerRequestDto;
import uk.gov.di.ipv.core.library.fixtures.TestFixtures;
import uk.gov.di.ipv.core.library.helpers.SecureTokenHelper;
import uk.gov.di.ipv.core.library.persistence.DataStore;
import uk.gov.di.ipv.core.library.persistence.item.VcStoreItem;
import uk.gov.di.ipv.core.library.service.ConfigurationService;

import java.net.URI;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Instant;
import java.util.Base64;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

@WireMockTest
@ExtendWith(MockitoExtension.class)
class CredentialIssuerServiceTest {

    private static final String TEST_IPV_SESSION_ID = SecureTokenHelper.generate();
    private static final String OAUTH_STATE = "oauth-state";
    private static final String TEST_AUTH_CODE = "test-auth-code";
    private static final String TEST_IP_ADDRESS = "192.168.1.100";

    @Mock private DataStore<VcStoreItem> mockDataStore;
    @Mock private ConfigurationService mockConfigurationService;

    private CredentialIssuerService credentialIssuerService;
    private final String testApiKey = "test-api-key";

    @BeforeEach
    void setUp() throws Exception {
        ECDSASigner signer = new ECDSASigner(getPrivateKey());

        credentialIssuerService =
                new CredentialIssuerService(mockDataStore, mockConfigurationService, signer);
    }

    @Test
    void validTokenResponse(WireMockRuntimeInfo wmRuntimeInfo) {
        Mockito.when(
                        mockConfigurationService.getSsmParameter(
                                ConfigurationVariable.JWT_TTL_SECONDS))
                .thenReturn("900");
        WireMock.stubFor(
                WireMock.post("/token")
                        .willReturn(
                                WireMock.aResponse()
                                        .withHeader(
                                                "Content-Type", "application/json;charset=utf-8")
                                        .withBody(
                                                "{\"access_token\":\"d09rUXQZ-4AjT6DNsRXj00KBt7Pqh8tFXBq8ul6KYQ4\",\"token_type\":\"Bearer\",\"expires_in\":3600}\n")));

        CredentialIssuerRequestDto credentialIssuerRequestDto =
                new CredentialIssuerRequestDto(
                        "1234",
                        "cred_issuer_id_1",
                        TEST_IPV_SESSION_ID,
                        "http://www.example.com/redirect",
                        OAUTH_STATE,
                        null,
                        null,
                        TEST_IP_ADDRESS);
        CredentialIssuerConfig credentialIssuerConfig =
                getStubCredentialIssuerConfig(wmRuntimeInfo);

        AccessToken accessToken =
                credentialIssuerService.exchangeCodeForToken(
                        TEST_AUTH_CODE, credentialIssuerConfig, testApiKey);
        AccessTokenType type = accessToken.getType();
        Assertions.assertEquals("Bearer", type.toString());
        Assertions.assertEquals(3600, accessToken.getLifetime());
        Assertions.assertEquals(
                "d09rUXQZ-4AjT6DNsRXj00KBt7Pqh8tFXBq8ul6KYQ4", accessToken.getValue());
    }

    @Test
    void validTokenResponseForAppJourney(WireMockRuntimeInfo wmRuntimeInfo) {
        Mockito.when(
                        mockConfigurationService.getSsmParameter(
                                ConfigurationVariable.JWT_TTL_SECONDS))
                .thenReturn("900");
        WireMock.stubFor(
                WireMock.post("/token")
                        .willReturn(
                                WireMock.aResponse()
                                        .withHeader(
                                                "Content-Type", "application/json;charset=utf-8")
                                        .withBody(
                                                "{\"access_token\":\"d09rUXQZ-4AjT6DNsRXj00KBt7Pqh8tFXBq8ul6KYQ4\",\"token_type\":\"Bearer\",\"expires_in\":3600}\n")));

        CredentialIssuerRequestDto credentialIssuerRequestDto =
                new CredentialIssuerRequestDto(
                        "1234",
                        "dcmaw",
                        TEST_IPV_SESSION_ID,
                        "http://www.example.com/redirect",
                        OAUTH_STATE,
                        null,
                        null,
                        TEST_IP_ADDRESS);
        CredentialIssuerConfig credentialIssuerConfig =
                getStubCredentialIssuerConfig(wmRuntimeInfo);

        AccessToken accessToken =
                credentialIssuerService.exchangeCodeForToken(
                        TEST_AUTH_CODE, credentialIssuerConfig, testApiKey);
        AccessTokenType type = accessToken.getType();
        Assertions.assertEquals("Bearer", type.toString());
        Assertions.assertEquals(3600, accessToken.getLifetime());
        Assertions.assertEquals(
                "d09rUXQZ-4AjT6DNsRXj00KBt7Pqh8tFXBq8ul6KYQ4", accessToken.getValue());
    }

    @Test
    void validTokenResponseWithoutApiKey(WireMockRuntimeInfo wmRuntimeInfo) {
        Mockito.when(
                        mockConfigurationService.getSsmParameter(
                                ConfigurationVariable.JWT_TTL_SECONDS))
                .thenReturn("900");
        WireMock.stubFor(
                WireMock.post("/token")
                        .willReturn(
                                WireMock.aResponse()
                                        .withHeader(
                                                "Content-Type", "application/json;charset=utf-8")
                                        .withBody(
                                                "{\"access_token\":\"d09rUXQZ-4AjT6DNsRXj00KBt7Pqh8tFXBq8ul6KYQ4\",\"token_type\":\"Bearer\",\"expires_in\":3600}\n")));

        CredentialIssuerRequestDto credentialIssuerRequestDto =
                new CredentialIssuerRequestDto(
                        "1234",
                        "cred_issuer_id_1",
                        TEST_IPV_SESSION_ID,
                        "http://www.example.com/redirect",
                        OAUTH_STATE,
                        null,
                        null,
                        TEST_IP_ADDRESS);
        CredentialIssuerConfig credentialIssuerConfig =
                getStubCredentialIssuerConfig(wmRuntimeInfo);

        AccessToken accessToken =
                credentialIssuerService.exchangeCodeForToken(
                        TEST_AUTH_CODE, credentialIssuerConfig, null);
        AccessTokenType type = accessToken.getType();
        Assertions.assertEquals("Bearer", type.toString());
        Assertions.assertEquals(3600, accessToken.getLifetime());
        Assertions.assertEquals(
                "d09rUXQZ-4AjT6DNsRXj00KBt7Pqh8tFXBq8ul6KYQ4", accessToken.getValue());
    }

    @Test
    void tokenErrorResponse(WireMockRuntimeInfo wmRuntimeInfo) {
        Mockito.when(
                        mockConfigurationService.getSsmParameter(
                                ConfigurationVariable.JWT_TTL_SECONDS))
                .thenReturn("900");
        var errorJson =
                "{ \"error\": \"invalid_request\", \"error_description\": \"Request was missing the 'redirect_uri' parameter.\", \"error_uri\": \"See the full API docs at https://authorization-server.com/docs/access_token\"}";
        WireMock.stubFor(
                WireMock.post("/token")
                        .willReturn(
                                WireMock.aResponse()
                                        .withStatus(400)
                                        .withHeader(
                                                "Content-Type", "application/json;charset=utf-8")
                                        .withBody(errorJson)));

        CredentialIssuerRequestDto credentialIssuerRequestDto =
                new CredentialIssuerRequestDto(
                        "1234",
                        "cred_issuer_id_1",
                        TEST_IPV_SESSION_ID,
                        "http://www.example.com/redirect",
                        OAUTH_STATE,
                        null,
                        null,
                        TEST_IP_ADDRESS);
        CredentialIssuerConfig credentialIssuerConfig =
                getStubCredentialIssuerConfig(wmRuntimeInfo);

        CredentialIssuerException exception =
                assertThrows(
                        CredentialIssuerException.class,
                        () ->
                                credentialIssuerService.exchangeCodeForToken(
                                        TEST_AUTH_CODE, credentialIssuerConfig, testApiKey));

        Assertions.assertEquals(HTTPResponse.SC_BAD_REQUEST, exception.getHttpStatusCode());
        Assertions.assertEquals(ErrorResponse.INVALID_TOKEN_REQUEST, exception.getErrorResponse());
    }

    @Test
    void invalidHeaderThrowsCredentialIssuerException(WireMockRuntimeInfo wmRuntimeInfo) {
        Mockito.when(
                        mockConfigurationService.getSsmParameter(
                                ConfigurationVariable.JWT_TTL_SECONDS))
                .thenReturn("900");
        WireMock.stubFor(
                WireMock.post("/token")
                        .willReturn(
                                WireMock.aResponse()
                                        .withHeader("Content-Type", "application/xml;charset=utf-8")
                                        .withBody(
                                                "{\"access_token\":\"d09rUXQZ-4AjT6DNsRXj00KBt7Pqh8tFXBq8ul6KYQ4\",\"token_type\":\"Bearer\",\"expires_in\":3600}\n")));

        CredentialIssuerRequestDto credentialIssuerRequestDto =
                new CredentialIssuerRequestDto(
                        "1234",
                        "cred_issuer_id_1",
                        TEST_IPV_SESSION_ID,
                        "http://www.example.com/redirect",
                        OAUTH_STATE,
                        null,
                        null,
                        TEST_IP_ADDRESS);
        CredentialIssuerConfig credentialIssuerConfig =
                getStubCredentialIssuerConfig(wmRuntimeInfo);
        CredentialIssuerException exception =
                assertThrows(
                        CredentialIssuerException.class,
                        () ->
                                credentialIssuerService.exchangeCodeForToken(
                                        TEST_AUTH_CODE, credentialIssuerConfig, testApiKey));

        Assertions.assertEquals(HTTPResponse.SC_SERVER_ERROR, exception.getHttpStatusCode());
        Assertions.assertEquals(
                ErrorResponse.FAILED_TO_EXCHANGE_AUTHORIZATION_CODE, exception.getErrorResponse());
    }

    @Test
    void expectedSuccessWhenSaveCredentials() throws Exception {
        ArgumentCaptor<VcStoreItem> userIssuedCredentialsItemCaptor =
                ArgumentCaptor.forClass(VcStoreItem.class);

        String credentialIssuerId = "cred_issuer_id_1";
        String userId = "user-id-1";

        credentialIssuerService.persistUserCredentials(
                SignedJWT.parse(TestFixtures.SIGNED_VC_1), credentialIssuerId, userId);
        Mockito.verify(mockDataStore)
                .create(
                        userIssuedCredentialsItemCaptor.capture(),
                        ArgumentMatchers.eq(ConfigurationVariable.VC_TTL));
        VcStoreItem vcStoreItem = userIssuedCredentialsItemCaptor.getValue();
        Assertions.assertEquals(userId, vcStoreItem.getUserId());
        Assertions.assertEquals(credentialIssuerId, vcStoreItem.getCredentialIssuer());
        Assertions.assertEquals(
                Instant.parse("2022-05-20T12:50:54Z"), vcStoreItem.getExpirationTime());
        Assertions.assertEquals(TestFixtures.SIGNED_VC_1, vcStoreItem.getCredential());
    }

    @Test
    void expectedExceptionWhenSaveCredentials() throws Exception {
        String credentialIssuerId = "cred_issuer_id_1";
        String userId = "user-id-1";

        Mockito.doThrow(new UnsupportedOperationException())
                .when(mockDataStore)
                .create(ArgumentMatchers.any(), ArgumentMatchers.any());

        SignedJWT signedJwt = SignedJWT.parse(TestFixtures.SIGNED_VC_1);
        CredentialIssuerException thrown =
                assertThrows(
                        CredentialIssuerException.class,
                        () ->
                                credentialIssuerService.persistUserCredentials(
                                        signedJwt, credentialIssuerId, userId));

        assertNotNull(thrown);
        Assertions.assertEquals(HTTPResponse.SC_SERVER_ERROR, thrown.getHttpStatusCode());
        Assertions.assertEquals(ErrorResponse.FAILED_TO_SAVE_CREDENTIAL, thrown.getErrorResponse());
    }

    @Test
    void getVerifiableCredentialCorrectlyCallsACredentialIssuer(WireMockRuntimeInfo wmRuntimeInfo) {
        WireMock.stubFor(
                WireMock.post("/credentials/issue")
                        .willReturn(
                                WireMock.aResponse()
                                        .withHeader("Content-Type", "application/jwt;charset=utf-8")
                                        .withBody(TestFixtures.SIGNED_VC_1)));

        CredentialIssuerConfig credentialIssuerConfig =
                getStubCredentialIssuerConfig(wmRuntimeInfo);

        BearerAccessToken accessToken = new BearerAccessToken();

        List<SignedJWT> credentials =
                credentialIssuerService.getVerifiableCredential(
                        accessToken, credentialIssuerConfig, testApiKey);

        Assertions.assertEquals(TestFixtures.SIGNED_VC_1, credentials.get(0).serialize());

        WireMock.verify(
                WireMock.postRequestedFor(WireMock.urlEqualTo("/credentials/issue"))
                        .withHeader(
                                "Authorization",
                                WireMock.equalTo("Bearer " + accessToken.getValue())));
    }

    @Test
    void getVerifiableCredentialCorrectlyCallsACredentialIssuerWithoutApiKey(
            WireMockRuntimeInfo wmRuntimeInfo) {
        WireMock.stubFor(
                WireMock.post("/credentials/issue")
                        .willReturn(
                                WireMock.aResponse()
                                        .withHeader("Content-Type", "application/jwt;charset=utf-8")
                                        .withBody(TestFixtures.SIGNED_VC_1)));

        CredentialIssuerConfig credentialIssuerConfig =
                getStubCredentialIssuerConfig(wmRuntimeInfo);

        BearerAccessToken accessToken = new BearerAccessToken();

        List<SignedJWT> credentials =
                credentialIssuerService.getVerifiableCredential(
                        accessToken, credentialIssuerConfig, null);

        Assertions.assertEquals(TestFixtures.SIGNED_VC_1, credentials.get(0).serialize());

        WireMock.verify(
                WireMock.postRequestedFor(WireMock.urlEqualTo("/credentials/issue"))
                        .withHeader(
                                "Authorization",
                                WireMock.equalTo("Bearer " + accessToken.getValue())));
    }

    @Test
    void getVerifiableCredentialCorrectlyCallsCriAndCanHandleJsonResponse(
            WireMockRuntimeInfo wmRuntimeInfo) throws JsonProcessingException {
        ObjectMapper objectMapper = new ObjectMapper();
        WireMock.stubFor(
                WireMock.post("/credentials/issue")
                        .willReturn(
                                WireMock.aResponse()
                                        .withHeader(
                                                "Content-Type", "application/json;charset=utf-8")
                                        .withBody(
                                                objectMapper.writeValueAsString(
                                                        TestFixtures.DCMAW_SUCCESS_RESPONSE))));

        CredentialIssuerConfig credentialIssuerConfig =
                getStubCredentialIssuerConfig(wmRuntimeInfo);

        BearerAccessToken accessToken = new BearerAccessToken();

        List<SignedJWT> credentials =
                credentialIssuerService.getVerifiableCredential(
                        accessToken, credentialIssuerConfig, null);

        Assertions.assertEquals(TestFixtures.SIGNED_VC_1, credentials.get(0).serialize());

        WireMock.verify(
                WireMock.postRequestedFor(WireMock.urlEqualTo("/credentials/issue"))
                        .withHeader(
                                "Authorization",
                                WireMock.equalTo("Bearer " + accessToken.getValue())));
    }

    @Test
    void getVerifiableCredentialThrowsIfResponseIsNotOk(WireMockRuntimeInfo wmRuntimeInfo) {

        WireMock.stubFor(
                WireMock.post("/credentials/issue")
                        .willReturn(
                                WireMock.aResponse()
                                        .withStatus(500)
                                        .withHeader("Content-Type", "text/plain")
                                        .withBody("Something bad happened...")));

        CredentialIssuerConfig credentialIssuerConfig =
                getStubCredentialIssuerConfig(wmRuntimeInfo);

        BearerAccessToken accessToken = new BearerAccessToken();

        CredentialIssuerException thrown =
                assertThrows(
                        CredentialIssuerException.class,
                        () ->
                                credentialIssuerService.getVerifiableCredential(
                                        accessToken, credentialIssuerConfig, testApiKey));

        Assertions.assertEquals(HTTPResponse.SC_SERVER_ERROR, thrown.getHttpStatusCode());
        Assertions.assertEquals(
                ErrorResponse.FAILED_TO_GET_CREDENTIAL_FROM_ISSUER, thrown.getErrorResponse());
    }

    @Test
    void getVerifiableCredentialThrowsIfNotResponseContentType(WireMockRuntimeInfo wmRuntimeInfo) {
        WireMock.stubFor(
                WireMock.post("/credentials/issue")
                        .willReturn(
                                WireMock.aResponse()
                                        .withHeader("Content-Type", "application/xml;charset=utf-8")
                                        .withBody(TestFixtures.SIGNED_VC_1)));

        CredentialIssuerConfig credentialIssuerConfig =
                getStubCredentialIssuerConfig(wmRuntimeInfo);
        BearerAccessToken accessToken = new BearerAccessToken();

        CredentialIssuerException thrown =
                assertThrows(
                        CredentialIssuerException.class,
                        () ->
                                credentialIssuerService.getVerifiableCredential(
                                        accessToken, credentialIssuerConfig, testApiKey));

        Assertions.assertEquals(HTTPResponse.SC_SERVER_ERROR, thrown.getHttpStatusCode());
        Assertions.assertEquals(
                ErrorResponse.FAILED_TO_GET_CREDENTIAL_FROM_ISSUER, thrown.getErrorResponse());
    }

    private CredentialIssuerConfig getStubCredentialIssuerConfig(
            WireMockRuntimeInfo wmRuntimeInfo) {
        return new CredentialIssuerConfig(
                "StubPassport",
                "any",
                URI.create("http://localhost:" + wmRuntimeInfo.getHttpPort() + "/token"),
                URI.create(
                        "http://localhost:" + wmRuntimeInfo.getHttpPort() + "/credentials/issue"),
                URI.create("http://localhost:" + wmRuntimeInfo.getHttpPort() + "/authorizeUrl"),
                "ipv-core",
                TestFixtures.EC_PUBLIC_JWK,
                TestFixtures.RSA_ENCRYPTION_PUBLIC_JWK,
                "test-audience",
                URI.create(
                        "http://localhost:"
                                + wmRuntimeInfo.getHttpPort()
                                + "/credential-issuer/callback?id=StubPassport"));
    }

    private ECPrivateKey getPrivateKey() throws InvalidKeySpecException, NoSuchAlgorithmException {
        return (ECPrivateKey)
                KeyFactory.getInstance("EC")
                        .generatePrivate(
                                new PKCS8EncodedKeySpec(
                                        Base64.getDecoder().decode(TestFixtures.EC_PRIVATE_KEY)));
    }
}
