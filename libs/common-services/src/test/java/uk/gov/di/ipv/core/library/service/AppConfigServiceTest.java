package uk.gov.di.ipv.core.library.service;

import com.fasterxml.jackson.databind.ObjectMapper;
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
import uk.gov.di.ipv.core.library.dto.OauthCriConfig;
import uk.gov.di.ipv.core.library.dto.RestCriConfig;
import uk.gov.di.ipv.core.library.persistence.item.CriOAuthSessionItem;
import uk.gov.di.ipv.core.library.testdata.CommonData;
import uk.org.webcompere.systemstubs.environment.EnvironmentVariables;
import uk.org.webcompere.systemstubs.jupiter.SystemStub;
import uk.org.webcompere.systemstubs.jupiter.SystemStubsExtension;

import java.net.URI;
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

@ExtendWith(MockitoExtension.class)
@ExtendWith(SystemStubsExtension.class)
class AppConfigServiceTest {

    private static String testRawParameters;

    @Mock AppConfigProvider appConfigProvider;
    @Mock SecretsProvider secretsProvider;

    AppConfigService configService;

    @SystemStub private EnvironmentVariables env = new EnvironmentVariables();

    @BeforeEach
    void setUp() throws Exception {
        if (testRawParameters == null) {
            testRawParameters =
                    new String(
                            CommonData.class
                                    .getResourceAsStream("/test-parameters.yaml")
                                    .readAllBytes(),
                            StandardCharsets.UTF_8);
        }

        configService = new AppConfigService(appConfigProvider, secretsProvider);
        lenient().when(appConfigProvider.get(any())).thenReturn(testRawParameters);
        configService.setConfiguration(ConfigService.generateConfiguration(testRawParameters));
    }

    // Core getters

    @Test
    void getComponentIdReturnComponentId() {
        var param = configService.getComponentId();
        assertEquals("https://identity.local.account.gov.uk", param);
    }

    @Test
    void getSisComponentIdReturnComponentId() {
        var param = configService.getSisComponentId();
        assertEquals("https://reuse-identity.build.account.gov.uk", param);
    }

    @Test
    void getCimitComponentIdReturnComponentId() {
        var param = configService.getCimitComponentId();
        assertEquals("https://cimit.stubs.account.gov.uk", param);
    }

    @Test
    void getBackendSessionTtl_returnsYamlValue() {
        assertEquals(3600L, configService.getBackendSessionTtl());
    }

    @Test
    void getCriResponseTtl_returnsYamlValue() {
        assertEquals(3600L, configService.getCriResponseTtl());
    }

    @Test
    void getSessionCredentialTtl_returnsYamlValue() {
        assertEquals(3600L, configService.getSessionCredentialTtl());
    }

    @Test
    void getBackendSessionTimeout_returnsYamlValue() {
        assertEquals(3600L, configService.getBackendSessionTimeout());
    }

    @Test
    void getOauthKeyCacheDurationMins_returnsYamlValue() {
        assertEquals(5L, configService.getOauthKeyCacheDurationMins());
    }

    @Test
    void shouldGetBearerTokenTtl() {
        var value = configService.getBearerTokenTtl();
        assertEquals(3600L, value);
    }

    @Test
    void shouldGetJwtTtlSeconds() {
        var value = configService.getJwtTtlSeconds();
        assertEquals(3600L, value);
    }

    @Test
    void shouldGetMaxAllowedAuthClientTtl() {
        var value = configService.getMaxAllowedAuthClientTtl();
        assertEquals(3600L, value);
    }

    @Test
    void getFraudCheckExpiryPeriodHours_returnsYamlValue() {
        assertEquals(720, configService.getFraudCheckExpiryPeriodHours());
    }

    @Test
    void getAuthCodeExpirySeconds_returnsYamlValue() {
        assertEquals(3600L, configService.getAuthCodeExpirySeconds());
    }

    // Client getters

    @Test
    void shouldGetClientValidRedirectUrls() {
        var value = configService.getClientValidRedirectUrls("orchStub");
        assertEquals(List.of("http://localhost:4500/callback"), value);
    }

    @Test
    void getValidScopes_returnsClientScopes() {
        assertEquals("openid", configService.getValidScopes("orchStub"));
    }

    @Test
    void getIssuer_returnsClientIssuer() {
        assertEquals("orchStub", configService.getIssuer("orchStub"));
    }

    // CRI getters

    @Test
    void getActiveConnection_returnsStubForAddress() {
        assertEquals("stub", configService.getActiveConnection(ADDRESS));
    }

    @Test
    void getAllowedSharedAttributes_returnsConfiguredList() {
        assertEquals("name,birthDate,address", configService.getAllowedSharedAttributes(ADDRESS));
    }

    @Test
    void isCredentialIssuerEnabledReadsFlag() {
        assertTrue(configService.isCredentialIssuerEnabled(ADDRESS.getId()));
    }

    @Test
    void getOauthCriConfigForConnection_unknownReturnsNull() {
        assertNull(configService.getOauthCriConfigForConnection("nope", ADDRESS));
    }

    @Test
    void getRestCriConfigForConnection_unknownReturnsNull() {
        assertNull(configService.getRestCriConfigForConnection("nope", ADDRESS));
    }

    // Environment variables & secrets

    @Test
    void getEnvironmentVariable_readsValue() {
        env.set("ENVIRONMENT", "dev123");
        assertEquals(
                "dev123", configService.getEnvironmentVariable(EnvironmentVariable.ENVIRONMENT));
    }

    @Test
    void getIntegerEnvironmentVariable_readsValue() {
        env.set("ENVIRONMENT", "7");
        assertEquals(
                7, configService.getIntegerEnvironmentVariable(EnvironmentVariable.ENVIRONMENT, 1));
    }

    @Test
    void getIntegerEnvironmentVariableDefault() {
        var result =
                configService.getIntegerEnvironmentVariable(EnvironmentVariable.ENVIRONMENT, 1);
        assertEquals(1, result);
    }

    @ParameterizedTest
    @MethodSource("SecretsManagerExceptions")
    void shouldReturnNullOnExceptionFromSecretsManager(Exception exception) {
        when(secretsProvider.get(any())).thenThrow(exception);

        var apiKey =
                configService.getSecret(
                        ConfigurationVariable.CREDENTIAL_ISSUER_API_KEY, PASSPORT.getId(), "stub");

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

    @Test
    void featureSetsOverrideConfiguration() {
        // Act & Assert
        assertEquals("https://identity.local.account.gov.uk", configService.getComponentId());
        assertEquals(3600L, configService.getBearerTokenTtl());

        configService.setFeatureSet(List.of("testFeature"));
        assertEquals("alternate-component-id", configService.getComponentId());
        assertEquals(3600L, configService.getBearerTokenTtl());
    }

    @Test
    void featureSetsOverrideConfigurationInCorrectOrder() {
        // Act & Assert
        configService.setFeatureSet(List.of("accountInterventions", "disableAccountInterventions"));
        assertFalse(configService.enabled("accountInterventionsEnabled"));

        configService.setFeatureSet(List.of("disableAccountInterventions", "accountInterventions"));
        assertTrue(configService.enabled("accountInterventionsEnabled"));
    }

    @Test
    void getParameterReturnsParametersWithFeatureOverride() {
        configService.setFeatureSet(List.of("testFeature"));
        var param = configService.getComponentId();
        assertEquals("alternate-component-id", param);
    }

    @Test
    void enabledTrueIfFeatureFlagEnabled() {
        assertTrue(configService.enabled("strategicAppEnabled"));
    }

    @Test
    void enabledFalseIfFeatureFlagNotEnabled() {
        assertFalse(configService.enabled("resetIdentity"));
    }

    @Test
    void enabledTrueIfFeatureFlagSetEnabled() {
        configService.setFeatureSet(List.of("accountInterventions"));
        assertTrue(configService.enabled("accountInterventionsEnabled"));
    }

    @Test
    void enabledFalseForMissingValue() {
        assertFalse(configService.enabled("not a feature flag"));
    }

    // Serialization sanity checks

    @Test
    void shouldNotSerializeDerivedProperties() throws Exception {
        var json = new ObjectMapper().writeValueAsString(configService.getConfiguration());
        assertFalse(json.contains("\"activeConfig\""), "derived getter must be ignored");
        assertFalse(json.contains("\"parsedEncryptionKey\""), "computed getter must be ignored");
    }

    // CI & CIMIT config

    @Test
    void shouldGetContraIndicatorConfigMap() {
        var map = configService.getContraIndicatorConfigMap();

        assertTrue(map.containsKey("NEEDS-ALTERNATE-DOC"));
        assertEquals(20, map.get("NEEDS-ALTERNATE-DOC").getDetectedScore());
        assertEquals(-20, map.get("NEEDS-ALTERNATE-DOC").getCheckedScore());
        assertEquals("needs-alternate-doc", map.get("NEEDS-ALTERNATE-DOC").getReturnCode());

        assertTrue(map.containsKey("ALWAYS-REQUIRED"));
        assertEquals(1, map.get("ALWAYS-REQUIRED").getDetectedScore());
        assertEquals(-1, map.get("ALWAYS-REQUIRED").getCheckedScore());
        assertEquals("always-required", map.get("ALWAYS-REQUIRED").getReturnCode());
    }

    @Test
    void shouldFetchCimitConfig() {
        var cimitConfig = configService.getCimitConfig();

        var route = cimitConfig.get("NEEDS-ALTERNATE-DOC").get(0);
        assertEquals("/journey/alternate-doc-invalid-dl", route.getEvent());
        assertEquals("drivingPermit", route.getDocument());
    }

    @Test
    void shouldThrowErrorOnInvalidCimitConfig() {
        var bad =
                """
                core:
                  cimit:
                    config:
                      notvalid: at-all
                """;
        when(appConfigProvider.get(any())).thenReturn(bad);
        configService = new AppConfigService(appConfigProvider, secretsProvider);

        assertThrows(IllegalArgumentException.class, () -> configService.getCimitConfig());
    }

    // Issuer map

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
        @SuppressWarnings("unused")
        private final OauthCriConfig expectedOauthCriConfig =
                OauthCriConfig.builder()
                        .tokenUrl(URI.create("https://testTokenUrl"))
                        .credentialUrl(URI.create("https://testCredentialUrl"))
                        .authorizeUrl(URI.create("https://testAuthoriseUrl"))
                        .clientId("ipv-core-test")
                        .signingKey(EC_PRIVATE_KEY_JWK)
                        .componentId("main-issuer")
                        .clientCallbackUrl(URI.create("https://testClientCallBackUrl"))
                        .requiresApiKey(true)
                        .requiresAdditionalEvidence(false)
                        .jwksUrl(URI.create("https://testWellKnownUrl"))
                        .build();

        @Test
        void getOauthCriActiveConnectionConfigShouldGetCredentialIssuerFromParameterStore() {
            var expected =
                    (OauthCriConfig)
                            configService
                                    .getConfiguration()
                                    .getCredentialIssuers()
                                    .getById(ADDRESS.getId())
                                    .getConnections()
                                    .get("stub");

            var result = configService.getOauthCriActiveConnectionConfig(ADDRESS);

            assertEquals(expected, result);
        }

        @Test
        void getOauthCriConfigShouldGetConfigForCriOauthSessionItem() {
            var expected =
                    (OauthCriConfig)
                            configService
                                    .getConfiguration()
                                    .getCredentialIssuers()
                                    .getById(ADDRESS.getId())
                                    .getConnections()
                                    .get("stub");

            var result =
                    configService.getOauthCriConfig(
                            CriOAuthSessionItem.builder()
                                    .criId(ADDRESS.getId())
                                    .connection("stub")
                                    .build());

            assertEquals(expected, result);
        }

        @Test
        void getOauthCriConfigForConnectionShouldGetOauthCriConfig() {
            var expected =
                    new ObjectMapper()
                            .convertValue(
                                    configService
                                            .getConfiguration()
                                            .getCredentialIssuers()
                                            .getById(ADDRESS.getId())
                                            .getConnections()
                                            .get("main"),
                                    OauthCriConfig.class);

            var result = configService.getOauthCriConfigForConnection("main", ADDRESS);

            assertEquals(expected, result);
        }

        @Test
        void getRestCriConfigShouldReturnARestCriConfig() {
            var expected =
                    new ObjectMapper()
                            .convertValue(
                                    configService
                                            .getConfiguration()
                                            .getCredentialIssuers()
                                            .getById(ADDRESS.getId())
                                            .getConnections()
                                            .get("main"),
                                    RestCriConfig.class);

            var result = configService.getRestCriConfigForConnection("main", ADDRESS);

            assertEquals(expected, result);
        }
    }
}
