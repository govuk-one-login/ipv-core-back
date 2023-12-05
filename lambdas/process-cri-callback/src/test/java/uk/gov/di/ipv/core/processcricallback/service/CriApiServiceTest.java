package uk.gov.di.ipv.core.processcricallback.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
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
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.dto.CredentialIssuerConfig;
import uk.gov.di.ipv.core.library.dto.CriCallbackRequest;
import uk.gov.di.ipv.core.library.helpers.JwtHelper;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.verifiablecredential.domain.VerifiableCredentialStatus;
import uk.gov.di.ipv.core.processcricallback.exception.CriApiException;

import java.net.URI;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.UUID;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.stubFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.client.WireMock.verify;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.JWT_TTL_SECONDS;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.DCMAW_SUCCESS_RESPONSE;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.EC_PRIVATE_KEY;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.EC_PUBLIC_JWK;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.RSA_ENCRYPTION_PUBLIC_JWK;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.VC_PASSPORT_NON_DCMAW_SUCCESSFUL;

@WireMockTest
@ExtendWith(MockitoExtension.class)
public class CriApiServiceTest {
    private static final String TEST_CRI_ID = "test_cri_id";
    private static final String API_KEY_HEADER = "x-api-key";
    private static final String TEST_API_KEY = "test_api_key";
    private static final String TEST_AUTHORISATION_CODE = "test_authorisation_code";
    private static final String TEST_ACCESS_TOKEN = "d09rUXQZ-4AjT6DNsRXj00KBt7Pqh8tFXBq8ul6KYQ4";
    @Mock private ConfigService mockConfigService;
    @Mock private ECDSASigner mockSigner;
    @InjectMocks private CriApiService criApiService;

    @BeforeEach
    void setUp(WireMockRuntimeInfo wmRuntimeInfo)
            throws InvalidKeySpecException, NoSuchAlgorithmException, JOSEException {
        mockSigner = new ECDSASigner(getPrivateKey());
        criApiService = new CriApiService(mockConfigService, mockSigner);

        var criConfig = getStubCredentialIssuerConfig(wmRuntimeInfo);
        when(mockConfigService.getCriConfig(any())).thenReturn(criConfig);
    }

    @Test
    void fetchAccessTokenShouldReturnAccessTokenForValidTokenResponse() throws CriApiException {
        // Arrange
        var callbackRequest = getValidCallbackRequest();
        when(mockConfigService.getCriPrivateApiKey(any())).thenReturn(TEST_API_KEY);
        when(mockConfigService.getSsmParameter(JWT_TTL_SECONDS)).thenReturn("900");

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

        // Act
        var accessToken = criApiService.fetchAccessToken(callbackRequest, null);

        // Assert
        var type = accessToken.getType();
        assertEquals(AccessTokenType.BEARER, type);
        assertEquals(3600, accessToken.getLifetime());
        assertEquals(TEST_ACCESS_TOKEN, accessToken.getValue());
    }

    @Test
    void fetchAccessTokenShouldReturnAccessTokenForNoApiKey() throws CriApiException {
        // Arrange
        var callbackRequest = getValidCallbackRequest();
        when(mockConfigService.getSsmParameter(JWT_TTL_SECONDS)).thenReturn("900");

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

        // Act
        var accessToken = criApiService.fetchAccessToken(callbackRequest, null);

        // Assert
        var type = accessToken.getType();
        assertEquals(AccessTokenType.BEARER, type);
        assertEquals(3600, accessToken.getLifetime());
        assertEquals(TEST_ACCESS_TOKEN, accessToken.getValue());
    }

    @Test
    void fetchAccessTokenThrowsCriApiExceptionForErrorTokenResponse() {
        // Arrange
        var callbackRequest = getValidCallbackRequest();
        when(mockConfigService.getCriPrivateApiKey(any())).thenReturn(TEST_API_KEY);
        when(mockConfigService.getSsmParameter(JWT_TTL_SECONDS)).thenReturn("900");

        stubFor(
                post("/token")
                        .willReturn(
                                aResponse()
                                        .withStatus(400)
                                        .withHeader(
                                                "Content-Type", "application/json;charset=utf-8")
                                        .withBody(
                                                "{ \"error\": \"invalid_request\", \"error_description\": \"Request was missing the 'redirect_uri' parameter.\", \"error_uri\": \"See the full API docs at https://authorization-server.com/docs/access_token\"}")));

        // Act & Assert
        var exception =
                assertThrows(
                        CriApiException.class,
                        () -> criApiService.fetchAccessToken(callbackRequest, null));

        assertEquals(HTTPResponse.SC_BAD_REQUEST, exception.getHttpStatusCode());
        assertEquals(ErrorResponse.INVALID_TOKEN_REQUEST, exception.getErrorResponse());
    }

    @Test
    void fetchAccessTokenThrowsCriApiExceptionForInvalidHeaderResponse() {
        // Arrange
        var callbackRequest = getValidCallbackRequest();
        when(mockConfigService.getCriPrivateApiKey(any())).thenReturn(TEST_API_KEY);
        when(mockConfigService.getSsmParameter(JWT_TTL_SECONDS)).thenReturn("900");

        stubFor(
                post("/token")
                        .willReturn(
                                aResponse()
                                        .withHeader("Content-Type", "application/xml;charset=utf-8")
                                        .withBody(
                                                "{\"access_token\":\"d09rUXQZ-4AjT6DNsRXj00KBt7Pqh8tFXBq8ul6KYQ4\",\"token_type\":\"Bearer\",\"expires_in\":3600}\n")));

        // Act & Assert
        var exception =
                assertThrows(
                        CriApiException.class,
                        () -> criApiService.fetchAccessToken(callbackRequest, null));

        assertEquals(HTTPResponse.SC_SERVER_ERROR, exception.getHttpStatusCode());
        assertEquals(
                ErrorResponse.FAILED_TO_EXCHANGE_AUTHORIZATION_CODE, exception.getErrorResponse());
    }

    @Test
    void buildFetchAccessTokenRequestShouldGetApiKeyIfPresent() throws CriApiException {
        // Arrange
        var callbackRequest = getValidCallbackRequest();
        when(mockConfigService.getCriPrivateApiKey(any())).thenReturn(TEST_API_KEY);
        when(mockConfigService.getSsmParameter(JWT_TTL_SECONDS)).thenReturn("900");

        // Act
        var request = criApiService.buildfetchAccessTokenRequest(callbackRequest, null);

        // Assert
        assertEquals(request.getHeaderMap().get(API_KEY_HEADER).get(0), TEST_API_KEY);
    }

    @Test
    public void buildFetchAccessTokenRequestShouldUseCorrectTokenEndpoint(
            WireMockRuntimeInfo wmRuntimeInfo) throws CriApiException {
        // Arrange
        var callbackRequest = getValidCallbackRequest();
        when(mockConfigService.getSsmParameter(JWT_TTL_SECONDS)).thenReturn("900");

        // Act
        var request = criApiService.buildfetchAccessTokenRequest(callbackRequest, null);

        // Assert
        assertEquals(
                String.format("http://localhost:%s/token", wmRuntimeInfo.getHttpPort()),
                request.getURL().toString());
    }

    @Test
    public void buildFetchAccessTokenRequestShouldHandleJOSEException() {
        // Arrange
        try (MockedStatic<JwtHelper> mockedJwtHelper = Mockito.mockStatic(JwtHelper.class)) {
            mockedJwtHelper
                    .when(() -> JwtHelper.createSignedJwtFromObject(any(), any()))
                    .thenThrow(new JOSEException("Test JOSE Exception"));
            when(mockConfigService.getSsmParameter(JWT_TTL_SECONDS)).thenReturn("900");

            var callbackRequest = getValidCallbackRequest();

            // Act & Assert
            assertThrows(
                    CriApiException.class,
                    () -> {
                        criApiService.buildfetchAccessTokenRequest(callbackRequest, null);
                    });
        }
    }

    @Test
    public void buildFetchAccessTokenRequestShouldFailGracefullyWithInvalidApiKey()
            throws CriApiException {
        // Arrange
        var callbackRequest = getValidCallbackRequest();
        when(mockConfigService.getCriPrivateApiKey(any())).thenReturn("InvalidApiKey");
        when(mockConfigService.getSsmParameter(JWT_TTL_SECONDS)).thenReturn("900");

        // Act
        var httpRequest = criApiService.buildfetchAccessTokenRequest(callbackRequest, null);

        // Assert
        assertNotEquals("InvalidApiKey", httpRequest.getAuthorization());
    }

    @Test
    public void buildFetchAccessTokenRequestShouldIncludeAuthorizationCodeInRequestBody()
            throws CriApiException {
        // Arrange
        var callbackRequest = getValidCallbackRequest();
        when(mockConfigService.getSsmParameter(JWT_TTL_SECONDS)).thenReturn("900");

        // Act
        var request = criApiService.buildfetchAccessTokenRequest(callbackRequest, null);

        // Assert
        assertTrue(request.getQuery().contains("code=" + TEST_AUTHORISATION_CODE));
    }

    @Test
    public void buildFetchAccessTokenRequestShouldIncludeRedirectionUriInRequestBody()
            throws CriApiException {
        // Arrange
        var callbackRequest = getValidCallbackRequest();
        when(mockConfigService.getSsmParameter(JWT_TTL_SECONDS)).thenReturn("900");

        // Act
        var request = criApiService.buildfetchAccessTokenRequest(callbackRequest, null);

        // Assert
        assertTrue(request.getQuery().contains("redirect_uri="));
    }

    @Test
    void getVerifiableCredentialCorrectlyCallsACredentialIssuer() throws CriApiException {
        // Arrange
        stubFor(
                post("/credentials/issue")
                        .willReturn(
                                aResponse()
                                        .withHeader("Content-Type", "application/jwt;charset=utf-8")
                                        .withBody(VC_PASSPORT_NON_DCMAW_SUCCESSFUL)));
        var accessToken = new BearerAccessToken();

        // Act
        var verifiableCredentialResponse =
                criApiService.fetchVerifiableCredential(
                        accessToken, getValidCallbackRequest(), null);

        // Assert
        assertEquals(
                VC_PASSPORT_NON_DCMAW_SUCCESSFUL,
                verifiableCredentialResponse.getVerifiableCredentials().get(0).serialize());
        verify(
                postRequestedFor(urlEqualTo("/credentials/issue"))
                        .withHeader("Authorization", equalTo("Bearer " + accessToken.getValue())));
    }

    @Test
    void getVerifiableCredentialCorrectlyGetsAPendingResponseFromCredentialIssuer()
            throws CriApiException {
        // Arrange
        final String testUserId = "urn:uuid" + UUID.randomUUID();
        final String pendingResponse =
                "{\"sub\":\""
                        + testUserId
                        + "\",\"https://vocab.account.gov.uk/v1/credentialStatus\":\"pending\"}";
        stubFor(
                post("/credentials/issue")
                        .willReturn(
                                aResponse()
                                        .withHeader(
                                                "Content-Type", "application/json;charset=utf-8")
                                        .withBody(pendingResponse)));
        var accessToken = new BearerAccessToken();

        // Act
        var verifiableCredentialResponse =
                criApiService.fetchVerifiableCredential(
                        accessToken, getValidCallbackRequest(), null);

        // Assert
        assertEquals(testUserId, verifiableCredentialResponse.getUserId());
        assertEquals(
                VerifiableCredentialStatus.PENDING,
                verifiableCredentialResponse.getCredentialStatus());
        verify(
                postRequestedFor(urlEqualTo("/credentials/issue"))
                        .withHeader("Authorization", equalTo("Bearer " + accessToken.getValue())));
    }

    @Test
    void getVerifiableCredentialCorrectlyCallsACredentialIssuerWithoutApiKey()
            throws CriApiException {
        // Arrange
        stubFor(
                post("/credentials/issue")
                        .willReturn(
                                aResponse()
                                        .withHeader("Content-Type", "application/jwt;charset=utf-8")
                                        .withBody(VC_PASSPORT_NON_DCMAW_SUCCESSFUL)));
        var accessToken = new BearerAccessToken("validToken");

        // Act
        var verifiableCredentialResponse =
                criApiService.fetchVerifiableCredential(
                        accessToken, getValidCallbackRequest(), null);

        // Assert
        assertEquals(
                VC_PASSPORT_NON_DCMAW_SUCCESSFUL,
                verifiableCredentialResponse.getVerifiableCredentials().get(0).serialize());
        verify(
                postRequestedFor(urlEqualTo("/credentials/issue"))
                        .withHeader("Authorization", equalTo("Bearer " + accessToken.getValue())));
    }

    @Test
    void getVerifiableCredentialCorrectlyCallsCriAndCanHandleJsonResponse()
            throws JsonProcessingException, CriApiException {
        // Arrange
        var objectMapper = new ObjectMapper();
        stubFor(
                post("/credentials/issue")
                        .willReturn(
                                aResponse()
                                        .withHeader(
                                                "Content-Type", "application/json;charset=utf-8")
                                        .withBody(
                                                objectMapper.writeValueAsString(
                                                        DCMAW_SUCCESS_RESPONSE))));
        var accessToken = new BearerAccessToken("validToken");

        // Act
        var verifiableCredentialResponse =
                criApiService.fetchVerifiableCredential(
                        accessToken, getValidCallbackRequest(), null);

        // Assert
        assertEquals(
                VC_PASSPORT_NON_DCMAW_SUCCESSFUL,
                verifiableCredentialResponse.getVerifiableCredentials().get(0).serialize());
        verify(
                postRequestedFor(urlEqualTo("/credentials/issue"))
                        .withHeader("Authorization", equalTo("Bearer " + accessToken.getValue())));
    }

    @Test
    void getVerifiableCredentialThrowsIfResponseIsNotOk() {
        // Arrange
        stubFor(
                post("/credentials/issue")
                        .willReturn(
                                aResponse()
                                        .withStatus(500)
                                        .withHeader("Content-Type", "text/plain")
                                        .withBody("Something bad happened...")));

        // Act & Assert
        var thrown =
                assertThrows(
                        CriApiException.class,
                        () ->
                                criApiService.fetchVerifiableCredential(
                                        new BearerAccessToken("validToken"),
                                        getValidCallbackRequest(),
                                        null));

        assertEquals(HTTPResponse.SC_SERVER_ERROR, thrown.getHttpStatusCode());
        assertEquals(ErrorResponse.FAILED_TO_GET_CREDENTIAL_FROM_ISSUER, thrown.getErrorResponse());
    }

    @Test
    void getVerifiableCredentialThrowsIf404NotFoundFromDcmawCri() {
        // Arrange
        var callbackRequest = getValidCallbackRequest();
        callbackRequest.setCredentialIssuerId("dcmaw");

        stubFor(
                post("/credentials/issue")
                        .willReturn(
                                aResponse()
                                        .withStatus(404)
                                        .withHeader("Content-Type", "text/plain")
                                        .withBody("Something bad happened...")));

        // Act & Assert
        var thrown =
                assertThrows(
                        CriApiException.class,
                        () ->
                                criApiService.fetchVerifiableCredential(
                                        new BearerAccessToken("validToken"),
                                        callbackRequest,
                                        null));

        assertEquals(HTTPResponse.SC_NOT_FOUND, thrown.getHttpStatusCode());
        assertEquals(ErrorResponse.FAILED_TO_GET_CREDENTIAL_FROM_ISSUER, thrown.getErrorResponse());
    }

    @Test
    void getVerifiableCredentialThrowsIfNotResponseContentType() {
        // Arrange
        stubFor(
                post("/credentials/issue")
                        .willReturn(
                                aResponse()
                                        .withHeader("Content-Type", "application/xml;charset=utf-8")
                                        .withBody(VC_PASSPORT_NON_DCMAW_SUCCESSFUL)));

        // Act & Assert
        var thrown =
                assertThrows(
                        CriApiException.class,
                        () ->
                                criApiService.fetchVerifiableCredential(
                                        new BearerAccessToken("validToken"),
                                        getValidCallbackRequest(),
                                        null));

        assertEquals(HTTPResponse.SC_SERVER_ERROR, thrown.getHttpStatusCode());
        assertEquals(ErrorResponse.FAILED_TO_GET_CREDENTIAL_FROM_ISSUER, thrown.getErrorResponse());
    }

    @Test
    void buildFetchVerifiableCredentialRequestShouldSetCorrectHeaders() {
        // Arrange
        var callbackRequest = getValidCallbackRequest();
        when(mockConfigService.getCriPrivateApiKey(any())).thenReturn(TEST_API_KEY);

        // Act
        var request =
                criApiService.buildFetchVerifiableCredentialRequest(
                        new BearerAccessToken("validToken"), callbackRequest, null);

        // Assert
        assertEquals(TEST_API_KEY, request.getHeaderMap().get("x-api-key").get(0));
    }

    @Test
    void buildFetchVerifiableCredentialRequestShouldSetCorrectAuthorizationHeader() {
        // Arrange
        var callbackRequest = getValidCallbackRequest();

        // Act
        var request =
                criApiService.buildFetchVerifiableCredentialRequest(
                        new BearerAccessToken("validToken"), callbackRequest, null);

        // Assert
        assertEquals("Bearer validToken", request.getAuthorization());
    }

    @Test
    void buildFetchVerifiableCredentialRequestShouldSetCorrectCredentialUrl(
            WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        // Arrange
        var callbackRequest = getValidCallbackRequest();

        // Act
        var request =
                criApiService.buildFetchVerifiableCredentialRequest(
                        new BearerAccessToken("validToken"), callbackRequest, null);
        // Assert
        assertEquals(
                String.format("http://localhost:%s/credentials/issue", wmRuntimeInfo.getHttpPort()),
                request.getURL().toURI().toString());
    }

    private CriCallbackRequest getValidCallbackRequest() {
        return CriCallbackRequest.builder()
                .credentialIssuerId(TEST_CRI_ID)
                .authorizationCode(TEST_AUTHORISATION_CODE)
                .build();
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
                true,
                false);
    }

    private ECPrivateKey getPrivateKey() throws InvalidKeySpecException, NoSuchAlgorithmException {
        return (ECPrivateKey)
                KeyFactory.getInstance("EC")
                        .generatePrivate(
                                new PKCS8EncodedKeySpec(
                                        Base64.getDecoder().decode(EC_PRIVATE_KEY)));
    }
}
