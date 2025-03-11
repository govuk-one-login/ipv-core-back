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
import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
import uk.gov.di.ipv.core.library.dto.OauthCriConfig;
import uk.gov.di.ipv.core.library.exceptions.ConfigParameterNotFoundException;
import uk.gov.di.ipv.core.library.service.ConfigService;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.mockito.quality.Strictness.LENIENT;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.CLIENT_JWKS_URL;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.PUBLIC_KEY_MATERIAL_FOR_CORE_TO_VERIFY;
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
    private static final String TEST_KEY =
            "{\"kty\":\"RSA\",\"e\":\"AQAB\",\"use\":\"enc\",\"kid\":\"nfwejnfwefcojwnk\",\"n\":\"vyapkvJXLwpYRJjbkQD99V2gcPEUKrO3\"}"; // pragma: allowlist secret
    private static OauthCriConfig oauthCriConfig;

    @Captor private ArgumentCaptor<HttpRequest> httpRequestCaptor;
    @Mock private HttpClient mockHttpClient;
    @Mock private HttpResponse<String> mockHttpResponse;
    @Mock private ConfigService mockConfigService;
    @InjectMocks private OAuthKeyService oAuthKeyService;

    @Nested
    class GetEncryptionKey {
        @BeforeAll
        static void setUp() throws Exception {
            oauthCriConfig =
                    OauthCriConfig.builder()
                            .jwksUrl(new URI(TEST_JWKS_ENDPOINT))
                            .encryptionKey(TEST_KEY)
                            .componentId(TEST_ISSUER)
                            .build();
        }

        @BeforeEach
        void beforeEach() throws Exception {
            when(mockConfigService.getLongParameter(
                            ConfigurationVariable.OAUTH_KEY_CACHE_DURATION_MINS))
                    .thenReturn(5L);
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
        void getEncryptionKeyShouldReturnKeyFromConfigIfResponseHasNoEncryptionKeys()
                throws Exception {
            // Set up
            when(mockHttpResponse.body())
                    .thenReturn(
                            String.format("{\"keys\":[%s]}", RSA_ENCRYPTION_PUBLIC_JWK_NO_KEY_USE));

            // Act
            var key = oAuthKeyService.getEncryptionKey(oauthCriConfig);

            // Assert
            verify(mockHttpClient).send(httpRequestCaptor.capture(), any());
            assertEquals(RSAKey.parse(TEST_KEY), key);
        }

        @Test
        void getEncryptionKeyShouldReturnKeyFromConfigIfResponseReturnsEmptyArray()
                throws Exception {
            // Set up
            when(mockHttpResponse.body()).thenReturn("{\"keys\":[]}");

            // Act
            var key = oAuthKeyService.getEncryptionKey(oauthCriConfig);

            // Assert
            verify(mockHttpClient).send(httpRequestCaptor.capture(), any());
            assertEquals(RSAKey.parse(TEST_KEY), key);
        }

        @ParameterizedTest
        @ValueSource(ints = {400, 500})
        @MockitoSettings(strictness = LENIENT)
        void getEncryptionKeyShouldReturnKeyFromConfigIfRequestErrors(int errorCode)
                throws Exception {
            // Set up
            when(mockHttpResponse.statusCode()).thenReturn(errorCode);

            // Act
            var key = oAuthKeyService.getEncryptionKey(oauthCriConfig);

            // Assert
            verify(mockHttpClient).send(httpRequestCaptor.capture(), any());
            assertEquals(RSAKey.parse(TEST_KEY), key);
        }

        @Test
        @MockitoSettings(strictness = LENIENT)
        void getEncryptionKeyShouldReturnKeyFromConfigIfNoJwksUrl() throws Exception {
            var oauthConfigNoJwksUrl = OauthCriConfig.builder().encryptionKey(TEST_KEY).build();
            var key = oAuthKeyService.getEncryptionKey(oauthConfigNoJwksUrl);

            assertEquals(RSAKey.parse(TEST_KEY), key);
        }

        @Test
        void getEncryptionKeyShouldReturnCachedKeyIfItExistsAndIsNotExpired() throws Exception {
            // Act
            // First call to cache key
            oAuthKeyService.getEncryptionKey(oauthCriConfig);

            // Second call
            var secondKey = oAuthKeyService.getEncryptionKey(oauthCriConfig);

            // Assert
            verify(mockHttpClient, times(1)).send(httpRequestCaptor.capture(), any());
            assertEquals(RSAKey.parse(RSA_ENCRYPTION_PUBLIC_JWK), secondKey);
        }

        @Test
        void getEncryptionKeyShouldCallJwksEndpointIfCachedKeyIsExpired() throws Exception {
            // Set up
            when(mockConfigService.getLongParameter(
                            ConfigurationVariable.OAUTH_KEY_CACHE_DURATION_MINS))
                    .thenReturn(0L)
                    .thenReturn(5L);

            // Act
            // First call to cache key
            oAuthKeyService.getEncryptionKey(oauthCriConfig);

            // Second call
            var secondKey = oAuthKeyService.getEncryptionKey(oauthCriConfig);

            // Assert
            verify(mockHttpClient, times(2)).send(httpRequestCaptor.capture(), any());
            assertEquals(RSAKey.parse(RSA_ENCRYPTION_PUBLIC_JWK), secondKey);
        }
    }

    @Nested
    class GetClientSigningKey {
        @BeforeEach
        void beforeEach() throws Exception {
            when(mockConfigService.getLongParameter(
                            ConfigurationVariable.OAUTH_KEY_CACHE_DURATION_MINS))
                    .thenReturn(5L);
            when(mockConfigService.getParameter(CLIENT_JWKS_URL, TEST_CLIENT_ID))
                    .thenReturn(TEST_JWKS_ENDPOINT);
            when(mockHttpClient.<String>send(any(), any())).thenReturn(mockHttpResponse);
            when(mockHttpResponse.statusCode()).thenReturn(200);
        }

        @Test
        void shouldReturnKeyByKeyId() throws Exception {
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
            when(mockConfigService.getParameter(
                            PUBLIC_KEY_MATERIAL_FOR_CORE_TO_VERIFY, TEST_CLIENT_ID))
                    .thenReturn(EC_PRIVATE_KEY_JWK_WITH_DIFFERENT_KID);

            var headerWithNoKeyId = new JWSHeader.Builder(JWSAlgorithm.ES256).keyID(null).build();

            var signingKey = oAuthKeyService.getClientSigningKey(TEST_CLIENT_ID, headerWithNoKeyId);

            assertEquals(ECKey.parse(EC_PRIVATE_KEY_JWK_WITH_DIFFERENT_KID), signingKey);
        }

        @Test
        void shouldReturnConfigKeyWhenKeyIdNotFoundInJwkSet() throws Exception {
            when(mockConfigService.getParameter(
                            PUBLIC_KEY_MATERIAL_FOR_CORE_TO_VERIFY, TEST_CLIENT_ID))
                    .thenReturn(EC_PRIVATE_KEY_JWK_WITH_DIFFERENT_KID);
            when(mockHttpResponse.body()).thenReturn("{\"keys\":[]}");

            var signingKey =
                    oAuthKeyService.getClientSigningKey(TEST_CLIENT_ID, JWS_HEADER_WITH_KID);

            assertEquals(ECKey.parse(EC_PRIVATE_KEY_JWK_WITH_DIFFERENT_KID), signingKey);
        }

        @Test
        @MockitoSettings(strictness = LENIENT)
        void shouldReturnConfigKeyIfJwksUrlNotConfiguredForClient() throws Exception {
            when(mockConfigService.getParameter(CLIENT_JWKS_URL, TEST_CLIENT_ID))
                    .thenThrow(new ConfigParameterNotFoundException("boop"));
            when(mockConfigService.getParameter(
                            PUBLIC_KEY_MATERIAL_FOR_CORE_TO_VERIFY, TEST_CLIENT_ID))
                    .thenReturn(EC_PRIVATE_KEY_JWK_WITH_DIFFERENT_KID);

            var signingKey =
                    oAuthKeyService.getClientSigningKey(TEST_CLIENT_ID, JWS_HEADER_WITH_KID);

            assertEquals(ECKey.parse(EC_PRIVATE_KEY_JWK_WITH_DIFFERENT_KID), signingKey);
        }
    }
}
