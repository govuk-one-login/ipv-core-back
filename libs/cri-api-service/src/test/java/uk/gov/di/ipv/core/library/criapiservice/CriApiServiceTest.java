package uk.gov.di.ipv.core.library.criapiservice;

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
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.criapiservice.dto.CredentialRequestBodyDto;
import uk.gov.di.ipv.core.library.criapiservice.exception.CriApiException;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.dto.CriCallbackRequest;
import uk.gov.di.ipv.core.library.dto.OauthCriConfig;
import uk.gov.di.ipv.core.library.helpers.JwtHelper;
import uk.gov.di.ipv.core.library.helpers.SecureTokenHelper;
import uk.gov.di.ipv.core.library.kmses256signer.KmsEs256SignerFactory;
import uk.gov.di.ipv.core.library.persistence.item.CriOAuthSessionItem;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.verifiablecredential.domain.VerifiableCredentialStatus;

import java.net.URI;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Clock;
import java.util.Base64;
import java.util.List;
import java.util.Map;
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
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.EC_PRIVATE_KEY;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.EC_PUBLIC_JWK;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.RSA_ENCRYPTION_PUBLIC_JWK;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.PASSPORT_NON_DCMAW_SUCCESSFUL_VC;

@WireMockTest
@ExtendWith(MockitoExtension.class)
class CriApiServiceTest {
    private static final String TEST_CRI_ID = "test-cri-id";
    private static final String DCMAW_CRI_ID = "dcmaw";
    private static final String API_KEY_HEADER = "x-api-key";
    private static final String TEST_API_KEY = "test_api_key";
    private static final String TEST_BASIC_AUTH_USER = "test_basic_auth_user";
    private static final String TEST_BASIC_AUTH_SECRET = "test_basic_auth_secret";
    private static final String TEST_AUTHORISATION_CODE = "test_authorisation_code";
    private static final String TEST_ACCESS_TOKEN = "d09rUXQZ-4AjT6DNsRXj00KBt7Pqh8tFXBq8ul6KYQ4";
    private static final VerifiableCredential PASSPORT_VC = PASSPORT_NON_DCMAW_SUCCESSFUL_VC;
    private static final Map<String, Object> DCMAW_SUCCESS_RESPONSE =
            Map.of(
                    "sub",
                    "urn:uuid:f81d4fae-7dec-11d0-a765-00a0c91e6bf6",
                    "https://vocab.account.gov.uk/v1/credentialJWT",
                    List.of(PASSPORT_VC.getVcString()));
    @Mock private ConfigService mockConfigService;
    @Mock private KmsEs256SignerFactory mockKmsEs256SignerFactory;
    private CriApiService criApiService;

    @BeforeEach
    void setUp(WireMockRuntimeInfo wmRuntimeInfo) {
        criApiService =
                new CriApiService(
                        mockConfigService,
                        mockKmsEs256SignerFactory,
                        SecureTokenHelper.getInstance(),
                        Clock.systemDefaultZone());

        var criConfig = getOauthCriConfig(wmRuntimeInfo);
        when(mockConfigService.getOauthCriConfig(any())).thenReturn(criConfig);
    }

    @Test
    void fetchAccessTokenShouldReturnAccessTokenForValidTokenResponse() throws Exception {
        // Arrange
        var callbackRequest = getValidCallbackRequest();
        when(mockConfigService.getCriPrivateApiKey(any())).thenReturn(TEST_API_KEY);
        when(mockConfigService.getSsmParameter(JWT_TTL_SECONDS)).thenReturn("900");
        when(mockKmsEs256SignerFactory.getSigner(any()))
                .thenReturn(new ECDSASigner(getPrivateKey()));

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
    void fetchAccessTokenShouldReturnAccessTokenForNoApiKey() throws Exception {
        // Arrange
        var callbackRequest = getValidCallbackRequest();
        when(mockConfigService.getSsmParameter(JWT_TTL_SECONDS)).thenReturn("900");
        when(mockKmsEs256SignerFactory.getSigner(any()))
                .thenReturn(new ECDSASigner(getPrivateKey()));

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
    void fetchAccessTokenThrowsCriApiExceptionForErrorTokenResponse() throws Exception {
        // Arrange
        var callbackRequest = getValidCallbackRequest();
        when(mockConfigService.getCriPrivateApiKey(any())).thenReturn(TEST_API_KEY);
        when(mockConfigService.getSsmParameter(JWT_TTL_SECONDS)).thenReturn("900");
        when(mockKmsEs256SignerFactory.getSigner(any()))
                .thenReturn(new ECDSASigner(getPrivateKey()));

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
    void fetchAccessTokenThrowsCriApiExceptionForInvalidHeaderResponse() throws Exception {
        // Arrange
        var callbackRequest = getValidCallbackRequest();
        when(mockConfigService.getCriPrivateApiKey(any())).thenReturn(TEST_API_KEY);
        when(mockConfigService.getSsmParameter(JWT_TTL_SECONDS)).thenReturn("900");
        when(mockKmsEs256SignerFactory.getSigner(any()))
                .thenReturn(new ECDSASigner(getPrivateKey()));

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
    void buildAccessTokenRequestWithJwtAuthenticationAndAuthorizationCodeShouldGetApiKeyIfPresent()
            throws Exception {
        // Arrange
        when(mockConfigService.getCriPrivateApiKey(any())).thenReturn(TEST_API_KEY);
        when(mockConfigService.getSsmParameter(JWT_TTL_SECONDS)).thenReturn("900");
        when(mockKmsEs256SignerFactory.getSigner(any()))
                .thenReturn(new ECDSASigner(getPrivateKey()));

        // Act
        var request =
                criApiService.buildAccessTokenRequestWithJwtAuthenticationAndAuthorizationCode(
                        TEST_CRI_ID, TEST_AUTHORISATION_CODE, null);

        // Assert
        assertEquals(TEST_API_KEY, request.getHeaderMap().get(API_KEY_HEADER).get(0));
    }

    @Test
    void
            buildAccessTokenRequestWithJwtAuthenticationAndAuthorizationCodeShouldUseCorrectTokenEndpoint(
                    WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        // Arrange
        when(mockConfigService.getSsmParameter(JWT_TTL_SECONDS)).thenReturn("900");
        when(mockKmsEs256SignerFactory.getSigner(any()))
                .thenReturn(new ECDSASigner(getPrivateKey()));

        // Act
        var request =
                criApiService.buildAccessTokenRequestWithJwtAuthenticationAndAuthorizationCode(
                        TEST_CRI_ID, TEST_AUTHORISATION_CODE, null);

        // Assert
        assertEquals(
                String.format("http://localhost:%s/token", wmRuntimeInfo.getHttpPort()),
                request.getURL().toString());
    }

    @Test
    void buildAccessTokenRequestWithJwtAuthenticationAndAuthorizationCodeShouldHandleJOSEException()
            throws Exception {
        // Arrange
        try (MockedStatic<JwtHelper> mockedJwtHelper = Mockito.mockStatic(JwtHelper.class)) {
            mockedJwtHelper
                    .when(() -> JwtHelper.createSignedJwtFromObject(any(), any()))
                    .thenThrow(new JOSEException("Test JOSE Exception"));
            when(mockConfigService.getSsmParameter(JWT_TTL_SECONDS)).thenReturn("900");
            when(mockKmsEs256SignerFactory.getSigner(any()))
                    .thenReturn(new ECDSASigner(getPrivateKey()));

            // Act & Assert
            assertThrows(
                    CriApiException.class,
                    () ->
                            criApiService
                                    .buildAccessTokenRequestWithJwtAuthenticationAndAuthorizationCode(
                                            TEST_CRI_ID, TEST_AUTHORISATION_CODE, null));
        }
    }

    @Test
    void
            buildAccessTokenRequestWithJwtAuthenticationAndAuthorizationCodeShouldFailGracefullyWithInvalidApiKey()
                    throws Exception {
        // Arrange
        when(mockConfigService.getCriPrivateApiKey(any())).thenReturn("InvalidApiKey");
        when(mockConfigService.getSsmParameter(JWT_TTL_SECONDS)).thenReturn("900");
        when(mockKmsEs256SignerFactory.getSigner(any()))
                .thenReturn(new ECDSASigner(getPrivateKey()));

        // Act
        var httpRequest =
                criApiService.buildAccessTokenRequestWithJwtAuthenticationAndAuthorizationCode(
                        TEST_CRI_ID, TEST_AUTHORISATION_CODE, null);

        // Assert
        assertNotEquals("InvalidApiKey", httpRequest.getAuthorization());
    }

    @Test
    void
            buildAccessTokenRequestWithJwtAuthenticationAndAuthorizationCodeShouldIncludeAuthorizationCodeInRequestBody()
                    throws Exception {
        // Arrange
        when(mockConfigService.getSsmParameter(JWT_TTL_SECONDS)).thenReturn("900");
        when(mockKmsEs256SignerFactory.getSigner(any()))
                .thenReturn(new ECDSASigner(getPrivateKey()));

        // Act
        var request =
                criApiService.buildAccessTokenRequestWithJwtAuthenticationAndAuthorizationCode(
                        TEST_CRI_ID, TEST_AUTHORISATION_CODE, null);

        // Assert
        assertTrue(request.getBody().contains("code=" + TEST_AUTHORISATION_CODE));
    }

    @Test
    void
            buildAccessTokenRequestWithJwtAuthenticationAndAuthorizationCodeShouldIncludeRedirectionUriInRequestBody()
                    throws Exception {
        // Arrange
        when(mockConfigService.getSsmParameter(JWT_TTL_SECONDS)).thenReturn("900");
        when(mockKmsEs256SignerFactory.getSigner(any()))
                .thenReturn(new ECDSASigner(getPrivateKey()));

        // Act
        var request =
                criApiService.buildAccessTokenRequestWithJwtAuthenticationAndAuthorizationCode(
                        TEST_CRI_ID, TEST_AUTHORISATION_CODE, null);

        // Assert
        assertTrue(request.getBody().contains("redirect_uri="));
    }

    @Test
    void
            buildAccessTokenRequestWithBasicAuthenticationAndClientCredentialsShouldBuildAnAuthorizationHeader()
                    throws Exception {
        // Arrange
        var criOauthSession = new CriOAuthSessionItem();
        criOauthSession.setCriId(TEST_CRI_ID);
        var expectedHeader =
                Base64.getEncoder()
                        .encodeToString(
                                (TEST_BASIC_AUTH_USER + ":" + TEST_BASIC_AUTH_SECRET).getBytes());

        // Act
        var request =
                criApiService.buildAccessTokenRequestWithBasicAuthenticationAndClientCredentials(
                        TEST_BASIC_AUTH_USER, TEST_BASIC_AUTH_SECRET, criOauthSession);

        // Assert
        assertEquals(
                "Basic dGVzdF9iYXNpY19hdXRoX3VzZXI6dGVzdF9iYXNpY19hdXRoX3NlY3JldA==",
                request.getAuthorization());
    }

    @Test
    void
            buildAccessTokenRequestWithBasicAuthenticationAndClientCredentialsShouldIncludeGrantTypeInRequestBody()
                    throws Exception {
        // Arrange
        var criOauthSession = new CriOAuthSessionItem();
        criOauthSession.setCriId(TEST_CRI_ID);

        // Act
        var request =
                criApiService.buildAccessTokenRequestWithBasicAuthenticationAndClientCredentials(
                        TEST_BASIC_AUTH_USER, TEST_BASIC_AUTH_SECRET, criOauthSession);

        // Assert
        assertEquals("grant_type=client_credentials", request.getBody());
    }

    @Test
    void getVerifiableCredentialCorrectlyCallsACredentialIssuer()
            throws CriApiException, JsonProcessingException {
        // Arrange
        stubFor(
                post("/credentials/issue")
                        .willReturn(
                                aResponse()
                                        .withHeader("Content-Type", "application/jwt;charset=utf-8")
                                        .withBody(PASSPORT_VC.getVcString())));
        var accessToken = new BearerAccessToken();

        // Act
        var verifiableCredentialResponse =
                criApiService.fetchVerifiableCredential(accessToken, TEST_CRI_ID, null);

        // Assert
        assertEquals(
                PASSPORT_VC.getVcString(),
                verifiableCredentialResponse.getVerifiableCredentials().get(0).trim());
        verify(
                postRequestedFor(urlEqualTo("/credentials/issue"))
                        .withHeader("Authorization", equalTo("Bearer " + accessToken.getValue())));
    }

    @Test
    void getVerifiableCredentialCorrectlyGetsAPendingResponseFromCredentialIssuer()
            throws CriApiException, JsonProcessingException {
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
                criApiService.fetchVerifiableCredential(accessToken, TEST_CRI_ID, null);

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
            throws CriApiException, JsonProcessingException {
        // Arrange
        stubFor(
                post("/credentials/issue")
                        .willReturn(
                                aResponse()
                                        .withHeader("Content-Type", "application/jwt;charset=utf-8")
                                        .withBody(PASSPORT_VC.getVcString())));
        var accessToken = new BearerAccessToken("validToken");

        // Act
        var verifiableCredentialResponse =
                criApiService.fetchVerifiableCredential(accessToken, TEST_CRI_ID, null);

        // Assert
        assertEquals(
                PASSPORT_VC.getVcString(),
                verifiableCredentialResponse.getVerifiableCredentials().get(0).trim());
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
                criApiService.fetchVerifiableCredential(accessToken, TEST_CRI_ID, null);

        // Assert
        assertEquals(
                PASSPORT_VC.getVcString(),
                verifiableCredentialResponse.getVerifiableCredentials().get(0));
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
                                        new BearerAccessToken("validToken"), TEST_CRI_ID, null));

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
                                        new BearerAccessToken("validToken"), DCMAW_CRI_ID, null));

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
                                        .withBody(PASSPORT_VC.getVcString())));

        // Act & Assert
        var thrown =
                assertThrows(
                        CriApiException.class,
                        () ->
                                criApiService.fetchVerifiableCredential(
                                        new BearerAccessToken("validToken"), TEST_CRI_ID, null));

        assertEquals(HTTPResponse.SC_SERVER_ERROR, thrown.getHttpStatusCode());
        assertEquals(ErrorResponse.FAILED_TO_GET_CREDENTIAL_FROM_ISSUER, thrown.getErrorResponse());
    }

    @Test
    void buildFetchVerifiableCredentialRequestShouldSetApiKeyHeader()
            throws JsonProcessingException {
        // Arrange
        when(mockConfigService.getCriPrivateApiKey(any())).thenReturn(TEST_API_KEY);

        // Act
        var request =
                criApiService.buildFetchVerifiableCredentialRequest(
                        new BearerAccessToken("validToken"), TEST_CRI_ID, null, null);

        // Assert
        assertEquals(TEST_API_KEY, request.getHeaderMap().get("x-api-key").get(0));
    }

    @Test
    void buildFetchVerifiableCredentialRequestShouldSetCorrectAuthorizationHeader()
            throws JsonProcessingException {
        // Act
        var request =
                criApiService.buildFetchVerifiableCredentialRequest(
                        new BearerAccessToken("validToken"), TEST_CRI_ID, null, null);

        // Assert
        assertEquals("Bearer validToken", request.getAuthorization());
    }

    @Test
    void buildFetchVerifiableCredentialRequestShouldSetContentTypeHeaderWhenABodyIsProvided()
            throws JsonProcessingException {
        // Arrange
        var body =
                new CredentialRequestBodyDto(
                        "userId",
                        "journeyId",
                        TEST_CRI_ID,
                        "RANDOM_STATE_VALUE",
                        "https://example.com");

        // Act
        var request =
                criApiService.buildFetchVerifiableCredentialRequest(
                        new BearerAccessToken("validToken"), TEST_CRI_ID, null, body);

        // Assert
        assertEquals("application/json", request.getHeaderMap().get("Content-Type").get(0));
    }

    @Test
    void buildFetchVerifiableCredentialRequestShouldSetBodyWhenABodyIsProvided()
            throws JsonProcessingException {
        // Arrange
        var body =
                new CredentialRequestBodyDto(
                        "userId",
                        "journeyId",
                        TEST_CRI_ID,
                        "RANDOM_STATE_VALUE",
                        "https://example.com");

        // Act
        var request =
                criApiService.buildFetchVerifiableCredentialRequest(
                        new BearerAccessToken("validToken"), TEST_CRI_ID, null, body);

        // Assert
        assertTrue(request.getBody().contains("userId"));
    }

    @Test
    void buildFetchVerifiableCredentialRequestShouldSetCorrectCredentialUrl(
            WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
        // Act
        var request =
                criApiService.buildFetchVerifiableCredentialRequest(
                        new BearerAccessToken("validToken"), TEST_CRI_ID, null, null);
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

    private OauthCriConfig getOauthCriConfig(WireMockRuntimeInfo wmRuntimeInfo) {
        return OauthCriConfig.builder()
                .tokenUrl(URI.create("http://localhost:" + wmRuntimeInfo.getHttpPort() + "/token"))
                .credentialUrl(
                        URI.create(
                                "http://localhost:"
                                        + wmRuntimeInfo.getHttpPort()
                                        + "/credentials/issue"))
                .authorizeUrl(
                        URI.create(
                                "http://localhost:"
                                        + wmRuntimeInfo.getHttpPort()
                                        + "/authorizeUrl"))
                .clientId("ipv-core")
                .signingKey(EC_PUBLIC_JWK)
                .encryptionKey(RSA_ENCRYPTION_PUBLIC_JWK)
                .componentId("test-audience")
                .clientCallbackUrl(
                        URI.create(
                                "http://localhost:"
                                        + wmRuntimeInfo.getHttpPort()
                                        + "/credential-issuer/callback?id=StubPassport"))
                .requiresApiKey(true)
                .requiresAdditionalEvidence(false)
                .build();
    }

    private ECPrivateKey getPrivateKey() throws InvalidKeySpecException, NoSuchAlgorithmException {
        return (ECPrivateKey)
                KeyFactory.getInstance("EC")
                        .generatePrivate(
                                new PKCS8EncodedKeySpec(
                                        Base64.getDecoder().decode(EC_PRIVATE_KEY)));
    }
}
