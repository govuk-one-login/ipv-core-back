package uk.gov.di.ipv.core.library.criapiservice;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.token.AccessTokenType;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.criapiservice.dto.AsyncCredentialRequestBodyDto;
import uk.gov.di.ipv.core.library.criapiservice.exception.CriApiException;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.dto.CriCallbackRequest;
import uk.gov.di.ipv.core.library.dto.OauthCriConfig;
import uk.gov.di.ipv.core.library.helpers.HttpRequestHelper;
import uk.gov.di.ipv.core.library.helpers.JwtHelper;
import uk.gov.di.ipv.core.library.helpers.SecureTokenHelper;
import uk.gov.di.ipv.core.library.persistence.item.CriOAuthSessionItem;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.signing.LocalECDSASigner;
import uk.gov.di.ipv.core.library.signing.SignerFactory;
import uk.gov.di.ipv.core.library.verifiablecredential.domain.VerifiableCredentialStatus;

import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;
import java.util.function.BiPredicate;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.domain.Cri.ADDRESS;
import static uk.gov.di.ipv.core.library.domain.Cri.DCMAW;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.EC_PRIVATE_KEY_JWK;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.TEST_EC_PUBLIC_JWK;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcWebPassportSuccessful;

@ExtendWith(MockitoExtension.class)
class CriApiServiceTest {
    private static final String API_KEY_HEADER = "x-api-key";
    private static final String TEST_API_KEY = "test_api_key";
    private static final String TEST_BASIC_AUTH_USER = "test_basic_auth_user";
    private static final String TEST_BASIC_AUTH_SECRET = "test_basic_auth_secret";
    private static final String TEST_AUTHORISATION_CODE = "test_authorisation_code";
    private static final String TEST_ACCESS_TOKEN =
            "d09rUXQZ-4AjT6DNsRXj00KBt7Pqh8tFXBq8ul6KYQ4"; // pragma: allowlist secret
    private static final VerifiableCredential PASSPORT_VC = vcWebPassportSuccessful();
    private static final Map<String, Object> DCMAW_SUCCESS_RESPONSE =
            Map.of(
                    "sub",
                    "urn:uuid:f81d4fae-7dec-11d0-a765-00a0c91e6bf6",
                    "https://vocab.account.gov.uk/v1/credentialJWT",
                    List.of(PASSPORT_VC.getVcString()));
    private static final OauthCriConfig TEST_CRI_CONFIG =
            OauthCriConfig.builder()
                    .tokenUrl(URI.create("http://localhost:" + 123 + "/token"))
                    .credentialUrl(URI.create("http://example.com/credentials/issue"))
                    .authorizeUrl(URI.create("http://example.com/authorize"))
                    .clientId("ipv-core")
                    .signingKey(TEST_EC_PUBLIC_JWK)
                    .componentId("test-audience")
                    .clientCallbackUrl(
                            URI.create(
                                    "http://example.com/credential-issue/callback?id=stubPassport"))
                    .requiresApiKey(true)
                    .requiresAdditionalEvidence(false)
                    .build();
    private static final BiPredicate<String, String> ALL_HEADERS = (a, b) -> true;
    private static final CriOAuthSessionItem TEST_CRI_SESSION = new CriOAuthSessionItem();
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    @Mock private ConfigService mockConfigService;
    @Mock private SignerFactory mockSignerFactory;
    @Mock private HttpClient mockHttpClient;
    @Mock private HttpResponse<String> mockResponse;
    @Captor private ArgumentCaptor<HttpRequest> httpRequestCaptor;
    private CriApiService criApiService;

    @BeforeEach
    void setUp() throws Exception {
        criApiService =
                new CriApiService(
                        mockConfigService,
                        mockSignerFactory,
                        SecureTokenHelper.getInstance(),
                        Clock.systemDefaultZone(),
                        new JavaHttpRequestSender(mockHttpClient));

        Mockito.lenient()
                .when(mockConfigService.getOauthCriConfig(any()))
                .thenReturn(TEST_CRI_CONFIG);
        Mockito.lenient().when(mockHttpClient.<String>send(any(), any())).thenReturn(mockResponse);
    }

    @Test
    void fetchAccessTokenShouldReturnAccessTokenForValidTokenResponse() throws Exception {
        // Arrange
        var callbackRequest = getValidCallbackRequest();
        when(mockConfigService.getSecret(any(), any(String[].class))).thenReturn(TEST_API_KEY);
        when(mockConfigService.getJwtTtlSeconds()).thenReturn(900L);
        when(mockSignerFactory.getSigner()).thenReturn(new LocalECDSASigner(getPrivateKey()));

        when(mockResponse.statusCode()).thenReturn(200);
        when(mockResponse.headers())
                .thenReturn(
                        HttpHeaders.of(
                                Map.of("Content-Type", List.of("application/json;charset=utf-8")),
                                ALL_HEADERS));
        when(mockResponse.body())
                .thenReturn(
                        String.format(
                                "{\"access_token\":\"%s\",\"token_type\":\"Bearer\",\"expires_in\":3600}",
                                TEST_ACCESS_TOKEN));

        // Act
        var accessToken = criApiService.fetchAccessToken(callbackRequest, TEST_CRI_SESSION);

        // Assert
        var type = accessToken.getType();
        assertEquals(AccessTokenType.BEARER, type);
        assertEquals(3600, accessToken.getLifetime());
        assertEquals(TEST_ACCESS_TOKEN, accessToken.getValue());

        verify(mockHttpClient).send(httpRequestCaptor.capture(), any());
        var request = httpRequestCaptor.getValue();
        assertEquals("POST", request.method());
        assertEquals(TEST_CRI_CONFIG.getTokenUrl(), request.uri());
        assertEquals(Optional.of(TEST_API_KEY), request.headers().firstValue(API_KEY_HEADER));
        var body = HttpRequestHelper.extractBody(request);
        assertTrue(body.contains("grant_type=authorization_code"));
        assertTrue(body.contains("code=" + TEST_AUTHORISATION_CODE));
        assertTrue(
                body.contains(
                        "redirect_uri="
                                + URLEncoder.encode(
                                        TEST_CRI_CONFIG.getClientCallbackUrl().toString(),
                                        StandardCharsets.UTF_8)));
    }

    @Test
    void fetchAccessTokenShouldReturnAccessTokenForNoApiKey() throws Exception {
        // Arrange
        var callbackRequest = getValidCallbackRequest();
        when(mockConfigService.getJwtTtlSeconds()).thenReturn(900L);
        when(mockSignerFactory.getSigner()).thenReturn(new LocalECDSASigner(getPrivateKey()));

        when(mockResponse.statusCode()).thenReturn(200);
        when(mockResponse.headers())
                .thenReturn(
                        HttpHeaders.of(
                                Map.of("Content-Type", List.of("application/json;charset=utf-8")),
                                ALL_HEADERS));
        when(mockResponse.body())
                .thenReturn(
                        String.format(
                                "{\"access_token\":\"%s\",\"token_type\":\"Bearer\",\"expires_in\":3600}",
                                TEST_ACCESS_TOKEN));

        // Act
        var accessToken = criApiService.fetchAccessToken(callbackRequest, TEST_CRI_SESSION);

        // Assert
        var type = accessToken.getType();
        assertEquals(AccessTokenType.BEARER, type);
        assertEquals(3600, accessToken.getLifetime());
        assertEquals(TEST_ACCESS_TOKEN, accessToken.getValue());

        verify(mockHttpClient).send(httpRequestCaptor.capture(), any());
        var request = httpRequestCaptor.getValue();
        assertEquals("POST", request.method());
        assertEquals(TEST_CRI_CONFIG.getTokenUrl(), request.uri());
        assertEquals(Optional.empty(), request.headers().firstValue(API_KEY_HEADER));
        var body = HttpRequestHelper.extractBody(request);
        assertTrue(body.contains("grant_type=authorization_code"));
        assertTrue(body.contains("code=" + TEST_AUTHORISATION_CODE));
        assertTrue(
                body.contains(
                        "redirect_uri="
                                + URLEncoder.encode(
                                        TEST_CRI_CONFIG.getClientCallbackUrl().toString(),
                                        StandardCharsets.UTF_8)));
    }

    @Test
    void fetchAccessTokenShouldReturnAccessTokenForBasicAuth() throws Exception {
        // Arrange
        when(mockResponse.statusCode()).thenReturn(200);
        when(mockResponse.headers())
                .thenReturn(
                        HttpHeaders.of(
                                Map.of("Content-Type", List.of("application/json;charset=utf-8")),
                                ALL_HEADERS));
        when(mockResponse.body())
                .thenReturn(
                        String.format(
                                "{\"access_token\":\"%s\",\"token_type\":\"Bearer\",\"expires_in\":3600}",
                                TEST_ACCESS_TOKEN));

        // Act
        var accessToken =
                criApiService.fetchAccessToken(
                        TEST_BASIC_AUTH_USER, TEST_BASIC_AUTH_SECRET, TEST_CRI_SESSION);

        // Assert
        var type = accessToken.getType();
        assertEquals(AccessTokenType.BEARER, type);
        assertEquals(3600, accessToken.getLifetime());
        assertEquals(TEST_ACCESS_TOKEN, accessToken.getValue());

        verify(mockHttpClient).send(httpRequestCaptor.capture(), any());
        var request = httpRequestCaptor.getValue();
        assertEquals("POST", request.method());
        assertEquals(TEST_CRI_CONFIG.getTokenUrl(), request.uri());
        var expectedAuth =
                String.format(
                        "Basic %s",
                        Base64.getEncoder()
                                .encodeToString(
                                        String.format(
                                                        "%s:%s",
                                                        TEST_BASIC_AUTH_USER,
                                                        TEST_BASIC_AUTH_SECRET)
                                                .getBytes(StandardCharsets.UTF_8)));
        assertEquals(Optional.of(expectedAuth), request.headers().firstValue("Authorization"));
        var body = HttpRequestHelper.extractBody(request);
        assertEquals("grant_type=client_credentials", body);
    }

    @Test
    void fetchAccessTokenThrowsCriApiExceptionForErrorTokenResponse() throws Exception {
        // Arrange
        var callbackRequest = getValidCallbackRequest();
        when(mockConfigService.getSecret(any(), any(String[].class))).thenReturn(TEST_API_KEY);
        when(mockConfigService.getJwtTtlSeconds()).thenReturn(900L);
        when(mockSignerFactory.getSigner()).thenReturn(new LocalECDSASigner(getPrivateKey()));

        when(mockResponse.statusCode()).thenReturn(400);
        when(mockResponse.headers())
                .thenReturn(
                        HttpHeaders.of(
                                Map.of("Content-Type", List.of("application/json;charset=utf-8")),
                                ALL_HEADERS));
        when(mockResponse.body())
                .thenReturn(
                        "{ \"error\": \"invalid_request\", \"error_description\": \"Request was missing the 'redirect_uri' parameter.\", \"error_uri\": \"See the full API docs at https://authorization-server.com/docs/access_token\"}");

        // Act & Assert
        var exception =
                assertThrows(
                        CriApiException.class,
                        () -> criApiService.fetchAccessToken(callbackRequest, TEST_CRI_SESSION));

        assertEquals(HTTPResponse.SC_BAD_REQUEST, exception.getHttpStatusCode());
        assertEquals(ErrorResponse.INVALID_TOKEN_REQUEST, exception.getErrorResponse());
    }

    @Test
    void fetchAccessTokenThrowsCriApiExceptionForInvalidHeaderResponse() throws Exception {
        // Arrange
        var callbackRequest = getValidCallbackRequest();
        when(mockConfigService.getSecret(any(), any(String[].class))).thenReturn(TEST_API_KEY);
        when(mockConfigService.getJwtTtlSeconds()).thenReturn(900L);
        when(mockSignerFactory.getSigner()).thenReturn(new LocalECDSASigner(getPrivateKey()));

        when(mockResponse.statusCode()).thenReturn(200);
        when(mockResponse.headers())
                .thenReturn(
                        HttpHeaders.of(
                                Map.of("Content-Type", List.of("application/xml;charset=utf-8")),
                                ALL_HEADERS));
        when(mockResponse.body())
                .thenReturn(
                        String.format(
                                "{\"access_token\":\"%s\",\"token_type\":\"Bearer\",\"expires_in\":3600}",
                                TEST_ACCESS_TOKEN));

        // Act & Assert
        var exception =
                assertThrows(
                        CriApiException.class,
                        () -> criApiService.fetchAccessToken(callbackRequest, TEST_CRI_SESSION));

        assertEquals(HTTPResponse.SC_SERVER_ERROR, exception.getHttpStatusCode());
        assertEquals(
                ErrorResponse.FAILED_TO_EXCHANGE_AUTHORIZATION_CODE, exception.getErrorResponse());
    }

    @Test
    void fetchAccessTokenThrowsCriApiExceptionForJOSEException() throws Exception {
        // Arrange
        var callbackRequest = getValidCallbackRequest();

        try (MockedStatic<JwtHelper> mockedJwtHelper = Mockito.mockStatic(JwtHelper.class)) {
            mockedJwtHelper
                    .when(() -> JwtHelper.createSignedJwt(any(), any()))
                    .thenThrow(new JOSEException("Test JOSE Exception"));
            when(mockConfigService.getJwtTtlSeconds()).thenReturn(900L);
            when(mockSignerFactory.getSigner()).thenReturn(new LocalECDSASigner(getPrivateKey()));

            // Act & Assert
            assertThrows(
                    CriApiException.class,
                    () -> criApiService.fetchAccessToken(callbackRequest, TEST_CRI_SESSION));
        }
    }

    @Test
    void getVerifiableCredentialCorrectlyCallsACredentialIssuer() throws Exception {
        // Arrange
        when(mockConfigService.getSecret(any(), any(String[].class))).thenReturn(TEST_API_KEY);

        when(mockResponse.statusCode()).thenReturn(200);
        when(mockResponse.headers())
                .thenReturn(
                        HttpHeaders.of(
                                Map.of("Content-Type", List.of("application/jwt;charset=utf-8")),
                                ALL_HEADERS));
        when(mockResponse.body()).thenReturn(PASSPORT_VC.getVcString());

        var accessToken = new BearerAccessToken();

        // Act
        var verifiableCredentialResponse =
                criApiService.fetchVerifiableCredential(accessToken, ADDRESS, TEST_CRI_SESSION);

        // Assert
        assertEquals(
                PASSPORT_VC.getVcString(),
                verifiableCredentialResponse.getVerifiableCredentials().get(0).trim());

        verify(mockHttpClient).send(httpRequestCaptor.capture(), any());
        var request = httpRequestCaptor.getValue();
        assertEquals("POST", request.method());
        assertEquals(TEST_CRI_CONFIG.getCredentialUrl(), request.uri());
        assertEquals(Optional.of(TEST_API_KEY), request.headers().firstValue(API_KEY_HEADER));
        assertEquals(
                Optional.of("Bearer " + accessToken.getValue()),
                request.headers().firstValue("Authorization"));
    }

    @Test
    void getVerifiableCredentialCorrectlyCallsACredentialIssuerWithoutApiKey() throws Exception {
        // Arrange
        when(mockResponse.statusCode()).thenReturn(200);
        when(mockResponse.headers())
                .thenReturn(
                        HttpHeaders.of(
                                Map.of("Content-Type", List.of("application/jwt;charset=utf-8")),
                                ALL_HEADERS));
        when(mockResponse.body()).thenReturn(PASSPORT_VC.getVcString());

        var accessToken = new BearerAccessToken("validToken");

        // Act
        var verifiableCredentialResponse =
                criApiService.fetchVerifiableCredential(accessToken, ADDRESS, TEST_CRI_SESSION);

        // Assert
        assertEquals(
                PASSPORT_VC.getVcString(),
                verifiableCredentialResponse.getVerifiableCredentials().get(0).trim());

        verify(mockHttpClient).send(httpRequestCaptor.capture(), any());
        var request = httpRequestCaptor.getValue();
        assertEquals("POST", request.method());
        assertEquals(TEST_CRI_CONFIG.getCredentialUrl(), request.uri());
        assertEquals(Optional.empty(), request.headers().firstValue(API_KEY_HEADER));
        assertEquals(
                Optional.of("Bearer " + accessToken.getValue()),
                request.headers().firstValue("Authorization"));
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

        when(mockResponse.statusCode()).thenReturn(200);
        when(mockResponse.headers())
                .thenReturn(
                        HttpHeaders.of(
                                Map.of("Content-Type", List.of("application/json;charset=utf-8")),
                                ALL_HEADERS));
        when(mockResponse.body()).thenReturn(pendingResponse);

        var accessToken = new BearerAccessToken();

        // Act
        var verifiableCredentialResponse =
                criApiService.fetchVerifiableCredential(accessToken, ADDRESS, TEST_CRI_SESSION);

        // Assert
        assertEquals(testUserId, verifiableCredentialResponse.getUserId());
        assertEquals(
                VerifiableCredentialStatus.PENDING,
                verifiableCredentialResponse.getCredentialStatus());
    }

    @Test
    void getVerifiableCredentialCorrectlyCallsCriAndCanHandleJsonResponse()
            throws JsonProcessingException, CriApiException {
        // Arrange
        when(mockResponse.statusCode()).thenReturn(200);
        when(mockResponse.headers())
                .thenReturn(
                        HttpHeaders.of(
                                Map.of("Content-Type", List.of("application/json;charset=utf-8")),
                                ALL_HEADERS));
        when(mockResponse.body())
                .thenReturn(OBJECT_MAPPER.writeValueAsString(DCMAW_SUCCESS_RESPONSE));

        var accessToken = new BearerAccessToken("validToken");

        // Act
        var verifiableCredentialResponse =
                criApiService.fetchVerifiableCredential(accessToken, ADDRESS, TEST_CRI_SESSION);

        // Assert
        assertEquals(
                PASSPORT_VC.getVcString(),
                verifiableCredentialResponse.getVerifiableCredentials().get(0));
    }

    @Test
    void getVerifiableCredentialThrowsIfResponseIsNotOk() {
        // Arrange
        when(mockResponse.statusCode()).thenReturn(500);
        when(mockResponse.headers())
                .thenReturn(
                        HttpHeaders.of(Map.of("Content-Type", List.of("text/plain")), ALL_HEADERS));
        when(mockResponse.body()).thenReturn("Something went wrong");

        // Act & Assert
        var thrown =
                assertThrows(
                        CriApiException.class,
                        () ->
                                criApiService.fetchVerifiableCredential(
                                        new BearerAccessToken("validToken"),
                                        ADDRESS,
                                        TEST_CRI_SESSION));

        assertEquals(HTTPResponse.SC_SERVER_ERROR, thrown.getHttpStatusCode());
        assertEquals(ErrorResponse.FAILED_TO_GET_CREDENTIAL_FROM_ISSUER, thrown.getErrorResponse());
    }

    @Test
    void getVerifiableCredentialThrowsIf404NotFoundFromDcmawCri() {
        // Arrange
        var callbackRequest = getValidCallbackRequest();
        callbackRequest.setCredentialIssuerId(DCMAW.getId());

        when(mockResponse.statusCode()).thenReturn(404);
        when(mockResponse.headers())
                .thenReturn(
                        HttpHeaders.of(Map.of("Content-Type", List.of("text/plain")), ALL_HEADERS));
        when(mockResponse.body()).thenReturn("Something went wrong");

        // Act & Assert
        var thrown =
                assertThrows(
                        CriApiException.class,
                        () ->
                                criApiService.fetchVerifiableCredential(
                                        new BearerAccessToken("validToken"),
                                        DCMAW,
                                        TEST_CRI_SESSION));

        assertEquals(HTTPResponse.SC_NOT_FOUND, thrown.getHttpStatusCode());
        assertEquals(ErrorResponse.FAILED_TO_GET_CREDENTIAL_FROM_ISSUER, thrown.getErrorResponse());
    }

    @Test
    void getVerifiableCredentialThrowsIfNotResponseContentType() {
        // Arrange
        when(mockResponse.statusCode()).thenReturn(200);
        when(mockResponse.headers())
                .thenReturn(
                        HttpHeaders.of(
                                Map.of("Content-Type", List.of("application/xml;charset=utf-8")),
                                ALL_HEADERS));
        when(mockResponse.body()).thenReturn(PASSPORT_VC.getVcString());

        // Act & Assert
        var thrown =
                assertThrows(
                        CriApiException.class,
                        () ->
                                criApiService.fetchVerifiableCredential(
                                        new BearerAccessToken("validToken"),
                                        ADDRESS,
                                        TEST_CRI_SESSION));

        assertEquals(HTTPResponse.SC_SERVER_ERROR, thrown.getHttpStatusCode());
        assertEquals(ErrorResponse.FAILED_TO_GET_CREDENTIAL_FROM_ISSUER, thrown.getErrorResponse());
    }

    @Test
    void getVerifiableCredentialCorrectlyCallsACredentialIssuerWithAnAsyncRequestBody()
            throws Exception {
        // Arrange
        var body =
                new AsyncCredentialRequestBodyDto(
                        "userId",
                        "journeyId",
                        ADDRESS.getId(),
                        "RANDOM_STATE_VALUE",
                        "https://example.com");

        when(mockResponse.statusCode()).thenReturn(200);
        when(mockResponse.headers())
                .thenReturn(
                        HttpHeaders.of(
                                Map.of("Content-Type", List.of("application/jwt;charset=utf-8")),
                                ALL_HEADERS));
        when(mockResponse.body()).thenReturn(PASSPORT_VC.getVcString());

        var accessToken = new BearerAccessToken();

        // Act
        var verifiableCredentialResponse =
                criApiService.fetchVerifiableCredential(
                        accessToken, ADDRESS, TEST_CRI_SESSION, body);

        // Assert
        assertEquals(
                PASSPORT_VC.getVcString(),
                verifiableCredentialResponse.getVerifiableCredentials().get(0).trim());

        verify(mockHttpClient).send(httpRequestCaptor.capture(), any());
        var request = httpRequestCaptor.getValue();
        assertEquals("POST", request.method());
        assertEquals(TEST_CRI_CONFIG.getCredentialUrl(), request.uri());
        assertEquals(Optional.of("application/json"), request.headers().firstValue("Content-Type"));
        assertEquals(
                Optional.of("Bearer " + accessToken.getValue()),
                request.headers().firstValue("Authorization"));
        assertEquals(
                OBJECT_MAPPER.writeValueAsString(body), HttpRequestHelper.extractBody(request));
    }

    private CriCallbackRequest getValidCallbackRequest() {
        return CriCallbackRequest.builder()
                .credentialIssuerId(ADDRESS.getId())
                .authorizationCode(TEST_AUTHORISATION_CODE)
                .build();
    }

    private ECKey getPrivateKey() throws Exception {
        return ECKey.parse(EC_PRIVATE_KEY_JWK);
    }
}
