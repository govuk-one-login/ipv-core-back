package uk.gov.di.ipv.core.library.oauthkeyservice;

import com.nimbusds.jose.jwk.RSAKey;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
import uk.gov.di.ipv.core.library.dto.OauthCriConfig;
import uk.gov.di.ipv.core.library.service.ConfigService;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.CALLS_REAL_METHODS;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.RSA_ENCRYPTION_PUBLIC_JWK;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.RSA_ENCRYPTION_PUBLIC_JWK_NO_KEY_USE;

@ExtendWith(MockitoExtension.class)
class OAuthKeyServiceTest {
    private static final String TEST_JWKS_ENDPOINT = "https://example.com/jwks";
    private static final String TEST_KEY =
            "{\"kty\":\"RSA\",\"e\":\"AQAB\",\"use\":\"enc\",\"kid\":\"nfwejnfwefcojwnk\",\"n\":\"vyapkvJXLwpYRJjbkQD99V2gcPEUKrO3\"}"; // pragma: allowlist secret
    private static OauthCriConfig oauthCriConfig;

    @Captor private ArgumentCaptor<HttpRequest> httpRequestCaptor;
    @Mock private HttpClient mockHttpClient;
    @Mock private HttpResponse<String> mockHttpResponse;
    @Mock private ConfigService mockConfigService;
    @InjectMocks private OAuthKeyService oAuthKeyService;

    @BeforeAll
    static void setUp() throws Exception {
        oauthCriConfig =
                OauthCriConfig.builder()
                        .jwksUrl(new URI(TEST_JWKS_ENDPOINT))
                        .encryptionKey(TEST_KEY)
                        .build();
    }

    static Stream<Arguments> jwksEndpointResponses() throws Exception {
        return Stream.of(
                Arguments.of(
                        String.format("{\"keys\":[%s]}", RSA_ENCRYPTION_PUBLIC_JWK),
                        RSAKey.parse(RSA_ENCRYPTION_PUBLIC_JWK)),
                Arguments.of(
                        String.format("{\"keys\":[%s]}", RSA_ENCRYPTION_PUBLIC_JWK_NO_KEY_USE),
                        RSAKey.parse(TEST_KEY)),
                Arguments.of("{\"keys\":[]}", RSAKey.parse(TEST_KEY)));
    }

    @Test
    void getEncryptionKeyShouldReturnKeyGivenASuccessfulRequestToJwksEndpoint() throws Exception {
        // Set up
        when(mockConfigService.getParameter(ConfigurationVariable.OAUTH_KEY_CACHE_DURATION_MINS))
                .thenReturn("5");
        when(mockHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(mockHttpResponse);
        when(mockHttpResponse.statusCode()).thenReturn(200);
        when(mockHttpResponse.body())
                .thenReturn(String.format("{\"keys\":[%s]}", RSA_ENCRYPTION_PUBLIC_JWK));

        // Act
        try (MockedStatic<HttpRequest.BodyPublishers> mockedBodyPublishers =
                mockStatic(HttpRequest.BodyPublishers.class, CALLS_REAL_METHODS)) {
            var key = oAuthKeyService.getEncryptionKey(oauthCriConfig);

            // Assert
            verify(mockHttpClient).send(httpRequestCaptor.capture(), any());
            assertEquals(RSAKey.parse(RSA_ENCRYPTION_PUBLIC_JWK), key);
        }
    }

    @Test
    void getEncryptionKeyShouldReturnKeyFromConfigIfResponseHasNoEncryptionKeys() throws Exception {
        // Set up
        when(mockHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(mockHttpResponse);
        when(mockHttpResponse.statusCode()).thenReturn(200);
        when(mockHttpResponse.body())
                .thenReturn(String.format("{\"keys\":[%s]}", RSA_ENCRYPTION_PUBLIC_JWK_NO_KEY_USE));

        // Act
        try (MockedStatic<HttpRequest.BodyPublishers> mockedBodyPublishers =
                mockStatic(HttpRequest.BodyPublishers.class, CALLS_REAL_METHODS)) {
            var key = oAuthKeyService.getEncryptionKey(oauthCriConfig);

            // Assert
            verify(mockHttpClient).send(httpRequestCaptor.capture(), any());
            assertEquals(RSAKey.parse(TEST_KEY), key);
        }
    }

    @Test
    void getEncryptionKeyShouldReturnKeyFromConfigIfResponseReturnsEmptyArray() throws Exception {
        // Set up
        when(mockHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(mockHttpResponse);
        when(mockHttpResponse.statusCode()).thenReturn(200);
        when(mockHttpResponse.body()).thenReturn("{\"keys\":[]}");

        // Act
        try (MockedStatic<HttpRequest.BodyPublishers> mockedBodyPublishers =
                mockStatic(HttpRequest.BodyPublishers.class, CALLS_REAL_METHODS)) {
            var key = oAuthKeyService.getEncryptionKey(oauthCriConfig);

            // Assert
            verify(mockHttpClient).send(httpRequestCaptor.capture(), any());
            assertEquals(RSAKey.parse(TEST_KEY), key);
        }
    }

    @ParameterizedTest
    @ValueSource(ints = {400, 500})
    void getEncryptionKeyShouldReturnKeyFromConfigIfRequestErrors(int errorCode) throws Exception {
        // Set up
        when(mockHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(mockHttpResponse);
        when(mockHttpResponse.statusCode()).thenReturn(errorCode);

        // Act
        try (MockedStatic<HttpRequest.BodyPublishers> mockedBodyPublishers =
                mockStatic(HttpRequest.BodyPublishers.class, CALLS_REAL_METHODS)) {
            var key = oAuthKeyService.getEncryptionKey(oauthCriConfig);

            // Assert
            verify(mockHttpClient).send(httpRequestCaptor.capture(), any());
            assertEquals(RSAKey.parse(TEST_KEY), key);
        }
    }

    @Test
    void getEncryptionKeyShouldReturnKeyFromConfigIfNoJwksUrl() throws Exception {
        var oauthConfigNoJwksUrl = OauthCriConfig.builder().encryptionKey(TEST_KEY).build();
        var key = oAuthKeyService.getEncryptionKey(oauthConfigNoJwksUrl);

        assertEquals(RSAKey.parse(TEST_KEY), key);
    }

    @Test
    void getEncryptionKeyShouldReturnCachedKeyIfItExistsAndIsNotExpired() throws Exception {
        // Set up
        when(mockConfigService.getParameter(ConfigurationVariable.OAUTH_KEY_CACHE_DURATION_MINS))
                .thenReturn("60");
        when(mockHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(mockHttpResponse);
        when(mockHttpResponse.statusCode()).thenReturn(200);
        when(mockHttpResponse.body())
                .thenReturn(String.format("{\"keys\":[%s]}", RSA_ENCRYPTION_PUBLIC_JWK));

        // Act
        try (MockedStatic<HttpRequest.BodyPublishers> mockedBodyPublishers =
                mockStatic(HttpRequest.BodyPublishers.class, CALLS_REAL_METHODS)) {
            // First call to cache key
            oAuthKeyService.getEncryptionKey(oauthCriConfig);

            // Second call
            var secondKey = oAuthKeyService.getEncryptionKey(oauthCriConfig);

            // Assert
            verify(mockHttpClient, times(1)).send(httpRequestCaptor.capture(), any());
            assertEquals(RSAKey.parse(RSA_ENCRYPTION_PUBLIC_JWK), secondKey);
        }
    }

    @Test
    void getEncryptionKeyShouldCallJwksEndpointIfCachedKeyIsExpired() throws Exception {
        // Set up
        when(mockConfigService.getParameter(ConfigurationVariable.OAUTH_KEY_CACHE_DURATION_MINS))
                .thenReturn("0");
        when(mockHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(mockHttpResponse);
        when(mockHttpResponse.statusCode()).thenReturn(200);
        when(mockHttpResponse.body())
                .thenReturn(String.format("{\"keys\":[%s]}", RSA_ENCRYPTION_PUBLIC_JWK));

        // Act
        try (MockedStatic<HttpRequest.BodyPublishers> mockedBodyPublishers =
                mockStatic(HttpRequest.BodyPublishers.class, CALLS_REAL_METHODS)) {
            // First call to cache key
            oAuthKeyService.getEncryptionKey(oauthCriConfig);

            // Second call
            var secondKey = oAuthKeyService.getEncryptionKey(oauthCriConfig);

            // Assert
            verify(mockHttpClient, times(2)).send(httpRequestCaptor.capture(), any());
            assertEquals(RSAKey.parse(RSA_ENCRYPTION_PUBLIC_JWK), secondKey);
        }
    }
}
