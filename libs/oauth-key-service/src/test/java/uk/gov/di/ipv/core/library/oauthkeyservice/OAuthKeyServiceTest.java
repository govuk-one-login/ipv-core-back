package uk.gov.di.ipv.core.library.oauthkeyservice;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.RSAKey;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import uk.gov.di.ipv.core.library.config.domain.ClientConfig;
import uk.gov.di.ipv.core.library.config.domain.Config;
import uk.gov.di.ipv.core.library.dto.OauthCriConfig;
import uk.gov.di.ipv.core.library.exceptions.ConfigParameterNotFoundException;
import uk.gov.di.ipv.core.library.exceptions.ConfigParseException;
import uk.gov.di.ipv.core.library.service.ConfigService;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.text.ParseException;
import java.util.NoSuchElementException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.mockito.quality.Strictness.LENIENT;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.EC_PRIVATE_KEY_JWK;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.EC_PRIVATE_KEY_JWK_WITH_DIFFERENT_KID;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.RSA_ENCRYPTION_PUBLIC_JWK;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.RSA_ENCRYPTION_PUBLIC_JWK_NO_KEY_USE;

@ExtendWith(MockitoExtension.class)
class OAuthKeyServiceTest {
    private static final JWSHeader JWS_HEADER_WITH_KID =
            new JWSHeader.Builder(JWSAlgorithm.ES256).keyID("test-fixtures-ec-key").build();
    private static final String TEST_JWKS_ENDPOINT = "https://example.com/jwks";
    private static final String TEST_ISSUER = "https://example.com/issuer";
    private static final String TEST_CLIENT_ID = "test-client-id";
    private static OauthCriConfig oauthCriConfig;

    @Captor private ArgumentCaptor<HttpRequest> httpRequestCaptor;
    @Mock private HttpClient mockHttpClient;
    @Mock private HttpResponse<String> mockHttpResponse;
    @Mock private ConfigService mockConfigService;
    @InjectMocks private OAuthKeyService oAuthKeyService;
    @Mock private Config mockConfig;
    @Mock private ClientConfig mockClientConfig;

    @Nested
    class GetEncryptionKey {
        @BeforeAll
        static void setUp() throws Exception {
            oauthCriConfig =
                    OauthCriConfig.builder()
                            .tokenUrl(new URI(""))
                            .credentialUrl(new URI(""))
                            .authorizeUrl(new URI(""))
                            .clientId("ipv-core")
                            .signingKey("")
                            .jwksUrl(new URI(TEST_JWKS_ENDPOINT))
                            .componentId(TEST_ISSUER)
                            .clientCallbackUrl(new URI(""))
                            .requiresApiKey(false)
                            .requiresAdditionalEvidence(false)
                            .build();
        }

        @BeforeEach
        void beforeEach() throws Exception {
            when(mockConfigService.getOauthKeyCacheDurationMins()).thenReturn(5L);
            when(mockHttpClient.<String>send(any(), any())).thenReturn(mockHttpResponse);
            when(mockHttpResponse.statusCode()).thenReturn(200);
            when(mockHttpResponse.body())
                    .thenReturn(String.format("{\"keys\":[%s]}", RSA_ENCRYPTION_PUBLIC_JWK));
        }

        @Test
        void getEncryptionKeyShouldReturnKeyGivenASuccessfulRequestToJwksEndpoint()
                throws Exception {
            // Act
            var key = oAuthKeyService.getEncryptionKey(oauthCriConfig);

            // Assert
            verify(mockHttpClient).send(httpRequestCaptor.capture(), any());
            assertEquals(RSAKey.parse(RSA_ENCRYPTION_PUBLIC_JWK), key);
        }

        @Test
        void getEncryptionKeyShouldThrowIfResponseHasNoEncryptionKeysAndNoCache() {
            // Set up
            when(mockHttpResponse.body())
                    .thenReturn(
                            String.format("{\"keys\":[%s]}", RSA_ENCRYPTION_PUBLIC_JWK_NO_KEY_USE));

            // Act & Assert
            assertThrows(
                    NoSuchElementException.class,
                    () -> oAuthKeyService.getEncryptionKey(oauthCriConfig));
        }

        @Test
        void getEncryptionKeyShouldThrowIfResponseReturnsEmptyArrayAndNoCache() {
            // Set up
            when(mockHttpResponse.body()).thenReturn("{\"keys\":[]}");

            // Act & Assert
            assertThrows(
                    NoSuchElementException.class,
                    () -> oAuthKeyService.getEncryptionKey(oauthCriConfig));
        }

        @ParameterizedTest
        @ValueSource(ints = {400, 500})
        @MockitoSettings(strictness = LENIENT)
        void getEncryptionKeyShouldThrowIfRequestErrorsAndNoCache(int errorCode) {
            // Set up
            when(mockHttpResponse.statusCode()).thenReturn(errorCode);

            // Act & Assert
            assertThrows(
                    ConfigParseException.class,
                    () -> oAuthKeyService.getEncryptionKey(oauthCriConfig));
        }

        @Test
        @MockitoSettings(strictness = LENIENT)
        void getEncryptionKeyShouldReturnKeyFromConfigIfNoJwksUrlAndNoCache() throws Exception {
            // Arrange
            var oauthConfigNoJwksUrl =
                    OauthCriConfig.builder()
                            .tokenUrl(new URI(""))
                            .credentialUrl(new URI(""))
                            .authorizeUrl(new URI(""))
                            .clientId("ipv-core")
                            .signingKey("")
                            .componentId(TEST_ISSUER)
                            .clientCallbackUrl(new URI(""))
                            .requiresApiKey(false)
                            .requiresAdditionalEvidence(false)
                            .build();

            // Act & Assert
            var exception =
                    assertThrows(
                            ConfigParameterNotFoundException.class,
                            () -> oAuthKeyService.getEncryptionKey(oauthConfigNoJwksUrl));
            assertEquals(
                    "Parameter not found in config: JWKS URL is not set in CRI config",
                    exception.getMessage());
        }

        @Test
        void getEncryptionKeyShouldReturnCachedKeyIfItExistsAndIsNotExpired() throws Exception {
            // First call populates cache with JWKS key
            oAuthKeyService.getEncryptionKey(oauthCriConfig);

            // Second call returns cached key; HTTP not called again
            var secondKey = oAuthKeyService.getEncryptionKey(oauthCriConfig);

            verify(mockHttpClient, times(1)).send(httpRequestCaptor.capture(), any());
            assertEquals(RSAKey.parse(RSA_ENCRYPTION_PUBLIC_JWK), secondKey);
        }

        @Test
        void getEncryptionKeyShouldCallJwksEndpointIfCachedKeyIsExpired() throws Exception {
            // Set up
            when(mockConfigService.getOauthKeyCacheDurationMins()).thenReturn(0L).thenReturn(5L);

            // Act
            // First call to cache key
            oAuthKeyService.getEncryptionKey(oauthCriConfig);

            // Second call
            var secondKey = oAuthKeyService.getEncryptionKey(oauthCriConfig);

            // Assert
            verify(mockHttpClient, times(2)).send(httpRequestCaptor.capture(), any());
            assertEquals(RSAKey.parse(RSA_ENCRYPTION_PUBLIC_JWK), secondKey);
        }

        @ParameterizedTest
        @ValueSource(ints = {400, 500})
        void getEncryptionKeyShouldReturnExpiredCacheIfResponseErrors(int errorCode)
                throws ParseException {
            // Set up expired cache
            when(mockConfigService.getOauthKeyCacheDurationMins()).thenReturn(0L);
            oAuthKeyService.getEncryptionKey(oauthCriConfig); // First call to cache key

            // Set up failed second call
            when(mockHttpResponse.statusCode()).thenReturn(errorCode);

            // Act
            var secondKey = oAuthKeyService.getEncryptionKey(oauthCriConfig);

            // Assert
            assertEquals(RSAKey.parse(RSA_ENCRYPTION_PUBLIC_JWK), secondKey);
        }
    }

    @Nested
    class GetClientSigningKey {
        @BeforeEach
        void beforeEach() throws Exception {
            when(mockConfigService.getConfiguration()).thenReturn(mockConfig);
            when(mockConfig.getClientConfig(TEST_CLIENT_ID)).thenReturn(mockClientConfig);

            when(mockHttpClient.<String>send(any(), any())).thenReturn(mockHttpResponse);
            when(mockHttpResponse.statusCode()).thenReturn(200);
        }

        @Test
        void shouldReturnKeyByKeyId() throws Exception {
            when(mockClientConfig.getJwksUrl()).thenReturn(TEST_JWKS_ENDPOINT);
            when(mockHttpResponse.body())
                    .thenReturn(
                            String.format(
                                    "{\"keys\":[%s, %s, %s]}",
                                    EC_PRIVATE_KEY_JWK,
                                    EC_PRIVATE_KEY_JWK_WITH_DIFFERENT_KID,
                                    RSA_ENCRYPTION_PUBLIC_JWK));

            var signingKey =
                    oAuthKeyService.getClientSigningKey(TEST_CLIENT_ID, JWS_HEADER_WITH_KID);
            assertEquals(ECKey.parse(EC_PRIVATE_KEY_JWK), signingKey);
        }

        @Test
        @MockitoSettings(strictness = LENIENT)
        void shouldReturnConfigKeyWhenNoKeyIdInHeader() throws Exception {
            when(mockClientConfig.getPublicKeyMaterialForCoreToVerify())
                    .thenReturn(EC_PRIVATE_KEY_JWK_WITH_DIFFERENT_KID);

            var headerNoKid = new JWSHeader.Builder(JWSAlgorithm.ES256).keyID(null).build();
            var signingKey = oAuthKeyService.getClientSigningKey(TEST_CLIENT_ID, headerNoKid);

            assertEquals(ECKey.parse(EC_PRIVATE_KEY_JWK_WITH_DIFFERENT_KID), signingKey);
        }

        @Test
        void shouldReturnConfigKeyWhenKeyIdNotFoundInJwkSet() throws Exception {
            when(mockClientConfig.getJwksUrl()).thenReturn(TEST_JWKS_ENDPOINT);
            when(mockHttpResponse.body()).thenReturn("{\"keys\":[]}");
            when(mockClientConfig.getPublicKeyMaterialForCoreToVerify())
                    .thenReturn(EC_PRIVATE_KEY_JWK_WITH_DIFFERENT_KID);

            var signingKey =
                    oAuthKeyService.getClientSigningKey(TEST_CLIENT_ID, JWS_HEADER_WITH_KID);
            assertEquals(ECKey.parse(EC_PRIVATE_KEY_JWK_WITH_DIFFERENT_KID), signingKey);
        }

        @Test
        @MockitoSettings(strictness = LENIENT)
        void shouldReturnConfigKeyIfJwksUrlNotConfiguredForClient() throws Exception {
            when(mockClientConfig.getJwksUrl())
                    .thenThrow(new ConfigParameterNotFoundException("boop"));
            when(mockClientConfig.getPublicKeyMaterialForCoreToVerify())
                    .thenReturn(EC_PRIVATE_KEY_JWK_WITH_DIFFERENT_KID);

            var signingKey =
                    oAuthKeyService.getClientSigningKey(TEST_CLIENT_ID, JWS_HEADER_WITH_KID);
            assertEquals(ECKey.parse(EC_PRIVATE_KEY_JWK_WITH_DIFFERENT_KID), signingKey);
        }
    }
}
