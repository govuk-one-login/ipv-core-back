package uk.gov.di.ipv.core.library.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import software.amazon.awssdk.services.secretsmanager.model.DecryptionFailureException;
import software.amazon.awssdk.services.secretsmanager.model.InternalServiceErrorException;
import software.amazon.awssdk.services.secretsmanager.model.InvalidParameterException;
import software.amazon.awssdk.services.secretsmanager.model.InvalidRequestException;
import software.amazon.awssdk.services.secretsmanager.model.ResourceNotFoundException;
import software.amazon.lambda.powertools.parameters.SecretsProvider;
import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
import uk.gov.di.ipv.core.library.domain.Cri;
import uk.gov.di.ipv.core.library.dto.CriConfig;
import uk.gov.di.ipv.core.library.dto.OauthCriConfig;
import uk.gov.di.ipv.core.library.dto.RestCriConfig;
import uk.gov.di.ipv.core.library.exceptions.ConfigException;
import uk.gov.di.ipv.core.library.exceptions.ConfigParameterNotFoundException;
import uk.gov.di.ipv.core.library.exceptions.ConfigParseException;
import uk.gov.di.ipv.core.library.exceptions.NoConfigForConnectionException;
import uk.gov.di.ipv.core.library.exceptions.NoCriForIssuerException;
import uk.gov.di.ipv.core.library.persistence.item.CriOAuthSessionItem;
import uk.org.webcompere.systemstubs.jupiter.SystemStubsExtension;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.domain.Cri.ADDRESS;
import static uk.gov.di.ipv.core.library.domain.Cri.DCMAW;
import static uk.gov.di.ipv.core.library.domain.Cri.PASSPORT;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.EC_PRIVATE_KEY_JWK;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.EC_PUBLIC_JWK_2;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.RSA_ENCRYPTION_PUBLIC_JWK;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.TEST_EC_PUBLIC_JWK;

@ExtendWith(MockitoExtension.class)
@ExtendWith(SystemStubsExtension.class)
class AppConfigServiceTest {
    private static final String TEST_RAW_PARAMETERS =
            """
        core:
          self:
            componentId: "test-component-id"
            bearerTokenTtl: 1800
            someStringList: "a,list,of,strings"
          credentialIssuers:
            address:
              activeConnection: main
              connections:
                main: '{
                  "componentId":"main-issuer",
                  "authorizeUrl":"https://testAuthoriseUrl",
                  "tokenUrl":"https://testTokenUrl",
                  "credentialUrl":"https://testCredentialUrl",
                  "clientId":"ipv-core-test",
                  "signingKey":"{\\"kty\\":\\"EC\\",\\"kid\\":\\"test-fixtures-ec-key\\",\\"use\\":\\"sig\\",\\"d\\":\\"OXt0P05ZsQcK7eYusgIPsqZdaBCIJiW4imwUtnaAthU\\",\\"crv\\":\\"P-256\\",\\"x\\":\\"E9ZzuOoqcVU4pVB9rpmTzezjyOPRlOmPGJHKi8RSlIM\\",\\"y\\":\\"KlTMZthHZUkYz5AleTQ8jff0TJiS3q2OB9L5Fw4xA04\\"}",
                  "encryptionKey":"{\\"kty\\":\\"RSA\\",\\"e\\":\\"AQAB\\",\\"use\\":\\"enc\\",\\"kid\\":\\"nfwejnfwefcojwnk\\",\\"n\\":\\"vyapkvJXLwpYRJjbkQD99V2gcPEUKrO3dwjcAA9TPkLucQEZvYZvb7-wfSHxlvJlJcdS20r5PKKmqdPeW3Y4ir3WsVVeiht2iOZUreUO5O3V3o7ImvEjPS_2_ZKMHCwUf51a6WGOaDjO87OX_bluV2dp01n-E3kiIl6RmWCVywjn13fX3jsX0LMCM_bt3HofJqiYhhNymEwh39oR_D7EE5sLUii2XvpTYPa6L_uPwdKa4vRl4h4owrWEJaJifMorGcvqhCK1JOHqgknN_3cb_ns9Px6ynQCeFXvBDJy4q71clkBq_EZs5227Y1S222wXIwUYN8w5YORQe3M-pCIh1Q\\"}",
                  "clientCallbackUrl":"https://testClientCallBackUrl",
                  "requiresApiKey":"true",
                  "requiresAdditionalEvidence":"false",
                  "jwksUrl":"https://testWellKnownUrl"
                }' # pragma: allowlist secret
                stub: '{
                  "componentId":"stub-issuer"
                }'
              historicSigningKeys: '{"kty":"EC","crv":"P-256","x":"E9ZzuOoqcVU4pVB9rpmTzezjyOPRlOmPGJHKi8RSlIM","y":"KlTMZthHZUkYz5AleTQ8jff0TJiS3q2OB9L5Fw4xA04"}/{"kty":"EC","crv":"P-256","x":"MjTFSolNjla11Dl8Zk9UpcpnMyWumfjIbO1E-0c8v-E","y":"xTdKNukh5sOvMgNTKjo0hVYNNcAS-N7X1R1S0cjllTo"}' # pragma: allowlist secret
            dcmaw:
              activeConnection: test
              connections:
                test: '{
                  "componentId":"alternate-issuer"
                }'
            criWithMalformedConfig:
              activeConnection: test
              connections:
                test: '{
                  componentId: alternate-issuer
                }'
          featureFlags:
            testFeatureFlag: false
            anotherFeatureFlag: true
          features:
            testFeature:
              featureFlags:
                testFeatureFlag: true
              self:
                componentId: "alternate-component-id"
          cimit:
            config: '{
              "NEEDS-ALTERNATE-DOC":[
                {"event":"/journey/alternate-doc-invalid-dl","document":"drivingPermit"}
              ]
            }'
          clients:
            testClient:
              validRedirectUrls: a,list,of,strings
    """;
    @Mock Cri criMock;
    @Mock SecretsProvider secretsProvider;
    AppConfigService configService;

    @BeforeEach
    void setUp() {
        configService = new AppConfigService(TEST_RAW_PARAMETERS, secretsProvider);
    }

    // Get parameter

    @Test
    void getParameterReturnsParameters() {
        // Act
        var param = configService.getParameter(ConfigurationVariable.COMPONENT_ID);

        // Assert
        assertEquals("test-component-id", param);
    }

    @Test
    void getParameterReturnsParametersWithoutUnrelatedFeatureOverride() {
        // Arrange
        configService.setFeatureSet(List.of("someOtherFeature"));

        // Act
        var param = configService.getParameter(ConfigurationVariable.COMPONENT_ID);

        // Assert
        assertEquals("test-component-id", param);
    }

    @Test
    void getParameterThrowsForMissingValue() {
        // Act & Assert
        assertThrows(
                ConfigParameterNotFoundException.class,
                () -> configService.getParameter(ConfigurationVariable.EVCS_APPLICATION_URL));
    }

    // Get specific parameters

    @Test
    void shouldReturnSlashSeparatedHistoricSigningKeys() {
        var result = configService.getHistoricSigningKeys(ADDRESS.getId());

        assertEquals(TEST_EC_PUBLIC_JWK, result.get(0));
        assertEquals(EC_PUBLIC_JWK_2, result.get(1));
    }

    @Test
    void shouldGetLongValueFromConfigIfSet() {
        // Act
        var value = configService.getLongParameter(ConfigurationVariable.BEARER_TOKEN_TTL);

        // Assert
        assertEquals(1800L, value);
    }

    @Test
    void shouldGetStringListValueFromConfigIfSet() {
        // Act
        var value =
                configService.getStringListParameter(
                        ConfigurationVariable.CLIENT_VALID_REDIRECT_URLS, "testClient");

        // Assert
        assertEquals(List.of("a", "list", "of", "strings"), value);
    }

    // Feature flags

    @Test
    void getParameterReturnsParametersWithFeatureOverride() {
        // Arrange
        configService.setFeatureSet(List.of("testFeature"));

        // Act
        var param = configService.getParameter(ConfigurationVariable.COMPONENT_ID);

        // Assert
        assertEquals("alternate-component-id", param);
    }

    @Test
    void enabledFalseIfFeatureFlagNotEnabled() {
        // Act & Assert
        assertFalse(configService.enabled("testFeatureFlag"));
    }

    @Test
    void enabledTrueIfFeatureFlagEnabled() {
        // Act & Assert
        assertTrue(configService.enabled("anotherFeatureFlag"));
    }

    @Test
    void enabledTrueIfFeatureFlagSetEnabled() {
        // Arrange
        configService.setFeatureSet(List.of("testFeature"));

        // Act & Assert
        assertTrue(configService.enabled("testFeatureFlag"));
    }

    @Test
    void enabledFalseForMissingValue() {
        // Act & Assert
        assertFalse(configService.enabled("not a feature flag"));
    }

    // Secrets

    @Test
    void shouldReturnNullOnDecryptionFailureFromSecretsManager() {
        // Arrange
        when(secretsProvider.get(any()))
                .thenThrow(
                        DecryptionFailureException.builder()
                                .message("Test decryption error")
                                .build());

        // Act
        var apiKey =
                configService.getSecret(
                        ConfigurationVariable.CREDENTIAL_ISSUER_API_KEY, PASSPORT.getId(), "stub");

        // Assert
        assertNull(apiKey);
    }

    @Test
    void shouldReturnNullOnInternalServiceErrorExceptionFromSecretsManager() {
        // Arrange
        when(secretsProvider.get(any()))
                .thenThrow(
                        InternalServiceErrorException.builder()
                                .message("Test internal service error")
                                .build());

        // Act
        var apiKey =
                configService.getSecret(
                        ConfigurationVariable.CREDENTIAL_ISSUER_API_KEY, PASSPORT.getId(), "stub");

        // Assert
        assertNull(apiKey);
    }

    @Test
    void shouldReturnNullOnInvalidParameterExceptionFromSecretsManager() {
        // Arrange
        when(secretsProvider.get(any()))
                .thenThrow(
                        InvalidParameterException.builder()
                                .message("Test invalid parameter error")
                                .build());

        // Act
        var apiKey =
                configService.getSecret(
                        ConfigurationVariable.CREDENTIAL_ISSUER_API_KEY, PASSPORT.getId(), "stub");

        // Assert
        assertNull(apiKey);
    }

    @Test
    void shouldReturnNullOnInvalidRequestExceptionFromSecretsManager() {
        // Arrange
        when(secretsProvider.get(any()))
                .thenThrow(
                        InvalidRequestException.builder()
                                .message("Test invalid request error")
                                .build());

        // Act
        var apiKey =
                configService.getSecret(
                        ConfigurationVariable.CREDENTIAL_ISSUER_API_KEY, PASSPORT.getId(), "stub");

        // Assert
        assertNull(apiKey);
    }

    @Test
    void shouldReturnNullOnResourceNotFoundExceptionFromSecretsManager() {
        // Arrange
        when(secretsProvider.get(any()))
                .thenThrow(
                        ResourceNotFoundException.builder()
                                .message("Test resource not found error")
                                .build());

        // Act
        var apiKey =
                configService.getSecret(
                        ConfigurationVariable.CREDENTIAL_ISSUER_API_KEY, PASSPORT.getId(), "stub");

        // Assert
        assertNull(apiKey);
    }

    // CI config

    @Test
    void shouldGetContraIndicatorConfigMap() {
        // Arrange
        when(secretsProvider.get(any()))
                .thenReturn(
                        "[{\"ci\":\"X01\",\"detectedScore\":3,\"checkedScore\":-3,\"returnCode\":\"1\"},{\"ci\":\"Z03\",\"detectedScore\":5,\"checkedScore\":-3,\"returnCode\":\"1\"}]");

        // Act
        var configMap = configService.getContraIndicatorConfigMap();

        // Assert
        assertEquals(2, configMap.size());
        assertTrue(configMap.containsKey("X01"));
        assertTrue(configMap.containsKey("Z03"));
        assertEquals("X01", configMap.get("X01").getCi());
        assertEquals(3, configMap.get("X01").getDetectedScore());
        assertEquals(-3, configMap.get("X01").getCheckedScore());
        assertEquals("1", configMap.get("X01").getReturnCode());
    }

    @Test
    void shouldReturnEmptyCollectionOnInvalidContraIndicatorConfigsMap() {
        // Arrange
        when(secretsProvider.get(any()))
                .thenReturn(
                        "[\"ci\":\"X01\",\"detectedScore\":3,\"checkedScore\":-3,\"returnCode\":\"1\"}]");

        // Act
        var configMap = configService.getContraIndicatorConfigMap();

        // Assert
        assertTrue(configMap.isEmpty());
    }

    @Test
    void getCriByIssuerReturnsCri() throws NoCriForIssuerException {
        // Act
        var cri = configService.getCriByIssuer("main-issuer");

        // Assert
        assertEquals(ADDRESS, cri);
    }

    // CIMIT config

    @Test
    void shouldFetchCimitConfig() throws ConfigException {
        // Act
        var cimitConfig = configService.getCimitConfig();

        // Assert
        assertEquals(
                "/journey/alternate-doc-invalid-dl",
                cimitConfig.get("NEEDS-ALTERNATE-DOC").get(0).event());
        assertEquals("drivingPermit", cimitConfig.get("NEEDS-ALTERNATE-DOC").get(0).document());
    }

    @Test
    void shouldThrowErrorOnInvalidCimitConfig() {
        // Arrange
        var TEST_RAW_PARAMETERS_INVALID_CIMIT =
                """
            core:
              cimit:
                config: '{
                  notvalid: at-all
                }'
        """;
        configService = new AppConfigService(TEST_RAW_PARAMETERS_INVALID_CIMIT, secretsProvider);

        // Act & Assert
        assertThrows(ConfigException.class, () -> configService.getCimitConfig());
    }

    // Get CRI by issuer

    @Test
    void shouldReturnCriForValidIssuers() throws NoCriForIssuerException {
        // Act & Assert
        assertEquals(ADDRESS, configService.getCriByIssuer("main-issuer"));
        assertEquals(ADDRESS, configService.getCriByIssuer("stub-issuer"));
        assertEquals(DCMAW, configService.getCriByIssuer("alternate-issuer"));
    }

    @Test
    void shouldErrorForInvalidIssuer() {
        // Act & Assert
        assertThrows(
                NoCriForIssuerException.class,
                () -> configService.getCriByIssuer("non-existent-issuer"));
    }

    @Test
    void getAllCrisByIssuerShouldReturnMapOfAllIssuersAndCri() {
        // Act
        var actual = configService.getAllCrisByIssuer();

        // Assert
        assertEquals(
                Map.of("stub-issuer", ADDRESS, "main-issuer", ADDRESS, "alternate-issuer", DCMAW),
                actual);
    }

    // OAuth CRI config

    @Nested
    @DisplayName("credential issuer config")
    class ActiveOauthCriConfig {
        private final OauthCriConfig expectedOauthCriConfig =
                OauthCriConfig.builder()
                        .tokenUrl(URI.create("https://testTokenUrl"))
                        .credentialUrl(URI.create("https://testCredentialUrl"))
                        .authorizeUrl(URI.create("https://testAuthoriseUrl"))
                        .clientId("ipv-core-test")
                        .signingKey(EC_PRIVATE_KEY_JWK)
                        .encryptionKey(RSA_ENCRYPTION_PUBLIC_JWK)
                        .componentId("main-issuer")
                        .clientCallbackUrl(URI.create("https://testClientCallBackUrl"))
                        .requiresApiKey(true)
                        .requiresAdditionalEvidence(false)
                        .jwksUrl(URI.create("https://testWellKnownUrl"))
                        .build();

        @Test
        void getOauthCriActiveConnectionConfigShouldGetCredentialIssuerFromParameterStore() {
            // Act
            var result = configService.getOauthCriActiveConnectionConfig(ADDRESS);

            // Assert
            assertEquals(expectedOauthCriConfig, result);
        }

        @Test
        void getOauthCriConfigShouldGetConfigForCriOauthSessionItem() {
            // Act
            var result =
                    configService.getOauthCriConfig(
                            CriOAuthSessionItem.builder()
                                    .criId(ADDRESS.getId())
                                    .connection("main")
                                    .build());

            // Assert
            assertEquals(expectedOauthCriConfig, result);
        }

        @Test
        void getOauthCriConfigForConnectionShouldGetOauthCriConfig() {
            // Act
            var result = configService.getOauthCriConfigForConnection("main", ADDRESS);

            // Assert
            assertEquals(expectedOauthCriConfig, result);
        }

        @Test
        void getOauthCriConfigForConnectionShouldThrowIfNoCriConfigFound() {
            // Act & Assert
            assertThrows(
                    NoConfigForConnectionException.class,
                    () -> configService.getOauthCriConfigForConnection("stub", Cri.PASSPORT));
        }

        @Test
        void getOauthCriConfigForConnectionShouldThrowIfCriConfigMalformed() {
            // Arrange
            when(criMock.getId()).thenReturn("criWithMalformedConfig");

            // Act & Assert
            assertThrows(
                    ConfigParseException.class,
                    () -> configService.getOauthCriConfigForConnection("test", criMock));
        }

        @Test
        void getRestCriConfigShouldReturnARestCriConfig() throws URISyntaxException {
            // Act
            var result = configService.getRestCriConfigForConnection("main", ADDRESS);

            // Assert
            assertEquals(
                    RestCriConfig.builder()
                            .credentialUrl(new URI("https://testCredentialUrl"))
                            .requiresApiKey(true)
                            .signingKey(EC_PRIVATE_KEY_JWK)
                            .componentId("main-issuer")
                            .build(),
                    result);
        }

        @Test
        void getCriConfigShouldReturnACriConfig() {
            // Act
            var result = configService.getCriConfig(ADDRESS);

            // Assert
            assertEquals(
                    CriConfig.builder()
                            .signingKey(EC_PRIVATE_KEY_JWK)
                            .componentId("main-issuer")
                            .build(),
                    result);
        }
    }
}
