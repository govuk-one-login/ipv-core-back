package uk.gov.di.ipv.core.library.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import software.amazon.awssdk.services.secretsmanager.model.DecryptionFailureException;
import software.amazon.awssdk.services.secretsmanager.model.InternalServiceErrorException;
import software.amazon.awssdk.services.secretsmanager.model.InvalidParameterException;
import software.amazon.awssdk.services.secretsmanager.model.InvalidRequestException;
import software.amazon.awssdk.services.secretsmanager.model.ResourceNotFoundException;
import software.amazon.lambda.powertools.parameters.AppConfigProvider;
import software.amazon.lambda.powertools.parameters.SecretsProvider;
import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
import uk.gov.di.ipv.core.library.config.EnvironmentVariable;
import uk.gov.di.ipv.core.library.domain.Cri;
import uk.gov.di.ipv.core.library.dto.CriConfig;
import uk.gov.di.ipv.core.library.dto.OauthCriConfig;
import uk.gov.di.ipv.core.library.dto.RestCriConfig;
import uk.gov.di.ipv.core.library.exceptions.ConfigException;
import uk.gov.di.ipv.core.library.exceptions.ConfigParameterNotFoundException;
import uk.gov.di.ipv.core.library.persistence.item.CriOAuthSessionItem;
import uk.gov.di.ipv.core.library.testdata.CommonData;
import uk.org.webcompere.systemstubs.jupiter.SystemStubsExtension;

import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.lenient;
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
    private static String TEST_RAW_PARAMETERS;

    @Mock Cri criMock;
    @Mock AppConfigProvider appConfigProvider;
    @Mock SecretsProvider secretsProvider;
    AppConfigService configService;

    @BeforeEach
    void setUp() throws Exception {
        if (TEST_RAW_PARAMETERS == null) {
            TEST_RAW_PARAMETERS =
                    new String(
                            CommonData.class
                                    .getResourceAsStream("/test-parameters.yaml")
                                    .readAllBytes(),
                            StandardCharsets.UTF_8);
        }

        configService = new AppConfigService(appConfigProvider, secretsProvider);
        lenient().when(appConfigProvider.get(any())).thenReturn(TEST_RAW_PARAMETERS);

        configService.setParameters(configService.updateParameters(TEST_RAW_PARAMETERS));
        configService.setConfiguration(ConfigService.generateConfiguration(TEST_RAW_PARAMETERS));
    }

    // Get parameter

    @Test
    void getParameterReturnsParameters() {
        // Act
        var param = configService.getConfiguration().getSelf().getComponentId().toString();

        // Assert
        assertEquals("https://identity.local.account.gov.uk", param);
    }

    @Test
    void getParameterReturnsParametersWithoutUnrelatedFeatureOverride() {
        // Arrange
        configService.setFeatureSet(List.of("someOtherFeature"));

        // Act
        var param = configService.getConfiguration().getSelf().getComponentId().toString();

        // Assert
        assertEquals("https://identity.local.account.gov.uk", param);
    }

    @Test
    void getParameterThrowsForMissingValue() {
        // Act & Assert
        assertThrows(
                ConfigParameterNotFoundException.class,
                () -> configService.getConfiguration().getEvcs().getApplicationUrl().toString());
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
        var value = configService.getBearerTokenTtl();

        // Assert
        assertEquals(3600L, value);
    }

    @Test
    void shouldGetStringListValueFromConfigIfSet() {
        // Act
        var value =
                configService.getStringListParameter(
                        ConfigurationVariable.CLIENT_VALID_REDIRECT_URLS, "orchStub");
        // Assert
        assertEquals(List.of("http://localhost:4500/callback"), value);
    }

    // Updated config

    @Test
    void getParameterReturnsUpdatedParameters() {
        // Act
        var componentId = configService.getConfiguration().getSelf().getComponentId().toString();
        var bearerTokenTtl =
                configService.getConfiguration().getSelf().getBearerTokenTtl().toString();

        // Assert
        assertEquals("https://identity.local.account.gov.uk", componentId);
        assertEquals("3600", bearerTokenTtl);

        // Arrange
        when(appConfigProvider.get(any()))
                .thenReturn(
                        """
              core:
                self:
                  componentId: "different-component-id"
            """);

        // Act
        componentId = configService.getConfiguration().getSelf().getComponentId().toString();

        // Assert
        assertEquals("different-component-id", componentId);
        assertThrows(
                ConfigParameterNotFoundException.class,
                () -> configService.getConfiguration().getSelf().getBearerTokenTtl().toString());
    }

    // Feature flags

    @Test
    void getParameterReturnsParametersWithFeatureOverride() {
        // Arrange
        configService.setFeatureSet(List.of("testFeature"));

        // Act
        var param = configService.getConfiguration().getSelf().getComponentId().toString();

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

    @ParameterizedTest
    @MethodSource("SecretsManagerExceptions")
    void shouldReturnNullOnExceptionFromSecretsManager(Exception exception) {
        // Arrange
        when(secretsProvider.get(any())).thenThrow(exception);

        // Act
        var apiKey =
                configService.getSecret(
                        ConfigurationVariable.CREDENTIAL_ISSUER_API_KEY, PASSPORT.getId(), "stub");

        // Assert
        assertNull(apiKey);
    }

    private static Stream<Arguments> SecretsManagerExceptions() {
        return Stream.of(
                Arguments.of(
                        DecryptionFailureException.builder()
                                .message("Test decryption error")
                                .build()),
                Arguments.of(
                        InternalServiceErrorException.builder()
                                .message("Test internal service error")
                                .build()),
                Arguments.of(
                        InvalidParameterException.builder()
                                .message("Test invalid parameter error")
                                .build()),
                Arguments.of(
                        InvalidRequestException.builder()
                                .message("Test invalid request error")
                                .build()),
                Arguments.of(
                        ResourceNotFoundException.builder()
                                .message("Test resource not found error")
                                .build()));
    }

    // CI config

    @Test
    void shouldGetContraIndicatorConfigMap() {
        // Arrange
        var testRawParametersCiConfig =
                """
            core:
              self:
                  ciScoringConfig:
                    - ci: "X01"
                      detectedScore: 3
                      checkedScore: -3
                      returnCode: "1"
                    - ci: "Z03"
                      detectedScore: 5
                      checkedScore: -3
                      returnCode: "1"
        """;
        when(appConfigProvider.get(any())).thenReturn(testRawParametersCiConfig);

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
        var testRawParametersInvalidCiConfig =
                """
            core:
              self:
                  ciScoringConfig:
                    - ci: "SomeCi"
                      invalidKey: "invalidValue"
        """;
        when(appConfigProvider.get(any())).thenReturn(testRawParametersInvalidCiConfig);

        // Act
        var configMap = configService.getContraIndicatorConfigMap();

        // Assert
        assertTrue(configMap.isEmpty());
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
        var testRawParametersInvalidCimit =
                """
            core:
              cimit:
                config:
                  notvalid: at-all
              credentialIssuers:
                address:
                  connections:
                    main:
                      componentId: main-issuer
        """;
        when(appConfigProvider.get(any())).thenReturn(testRawParametersInvalidCimit);
        configService = new AppConfigService(appConfigProvider, secretsProvider);

        // Act & Assert
        assertThrows(ConfigException.class, () -> configService.getCimitConfig());
    }

    // Get CRI by issuer

    @Test
    void shouldReturnIssuerCris() {
        var issuerCris = configService.getIssuerCris();

        assertEquals(ADDRESS, issuerCris.get("https://address-cri.stubs.account.gov.uk"));
        assertEquals(DCMAW, issuerCris.get("https://dcmaw-cri.stubs.account.gov.uk"));
        assertEquals(PASSPORT, issuerCris.get("https://passport-cri.stubs.account.gov.uk"));
        assertTrue(issuerCris.size() > 3);
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
                    ConfigParameterNotFoundException.class,
                    () -> configService.getOauthCriConfigForConnection("stub", Cri.PASSPORT));
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

    // Environment variables

    @Test
    void getIntegerEnvironmentVariableDefault() {
        // Act
        var result =
                configService.getIntegerEnvironmentVariable(EnvironmentVariable.ENVIRONMENT, 1);

        // Assert
        assertEquals(1, result);
    }
}
