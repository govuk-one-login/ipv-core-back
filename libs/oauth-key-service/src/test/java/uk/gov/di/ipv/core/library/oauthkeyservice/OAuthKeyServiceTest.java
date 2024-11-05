package uk.gov.di.ipv.core.library.oauthkeyservice;

import com.nimbusds.jose.jwk.RSAKey;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.dto.OauthCriConfig;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.CALLS_REAL_METHODS;
import static org.mockito.Mockito.mockStatic;
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
    @InjectMocks private OAuthKeyService oAuthKeyService;

    @BeforeEach
    void setUp() throws Exception {
        oAuthKeyService = new OAuthKeyService(mockHttpClient);
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

    @ParameterizedTest
    @MethodSource("jwksEndpointResponses")
    void getFirstValidEncryptionKeyShouldReturnKeyGivenASuccessfulRequestToJwksEndpoint(
            String jwksResponse, RSAKey expectedKey) throws Exception {
        // Set up
        when(mockHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(mockHttpResponse);
        when(mockHttpResponse.statusCode()).thenReturn(200);
        when(mockHttpResponse.body()).thenReturn(jwksResponse);

        // Act
        try (MockedStatic<HttpRequest.BodyPublishers> mockedBodyPublishers =
                mockStatic(HttpRequest.BodyPublishers.class, CALLS_REAL_METHODS)) {
            var key = oAuthKeyService.getValidEncryptionKey(oauthCriConfig);

            // Assert
            verify(mockHttpClient).send(httpRequestCaptor.capture(), any());
            assertEquals(expectedKey, key);
        }
    }

    @ParameterizedTest
    @ValueSource(ints = {400, 500})
    void getFirstValidEncryptionKeyShouldReturnKeyFromConfigIfRequestErrors(int errorCode)
            throws Exception {
        // Set up
        when(mockHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(mockHttpResponse);
        when(mockHttpResponse.statusCode()).thenReturn(errorCode);

        // Act
        try (MockedStatic<HttpRequest.BodyPublishers> mockedBodyPublishers =
                mockStatic(HttpRequest.BodyPublishers.class, CALLS_REAL_METHODS)) {
            var key = oAuthKeyService.getValidEncryptionKey(oauthCriConfig);

            // Assert
            verify(mockHttpClient).send(httpRequestCaptor.capture(), any());
            assertEquals(RSAKey.parse(TEST_KEY), key);
        }
    }

    @Test
    void getFirstValidEncryptionKeyShouldReturnKeyFromConfigIfNoJwksUrl() throws Exception {
        var oauthConfigNoJwksUrl = OauthCriConfig.builder().encryptionKey(TEST_KEY).build();
        var key = oAuthKeyService.getValidEncryptionKey(oauthConfigNoJwksUrl);

        assertEquals(RSAKey.parse(TEST_KEY), key);
    }
}
