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
import org.mockito.junit.jupiter.MockitoSettings;
import software.amazon.awssdk.services.ssm.model.ParameterNotFoundException;
import software.amazon.lambda.powertools.parameters.SSMProvider;
import software.amazon.lambda.powertools.parameters.SecretsProvider;
import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
import uk.gov.di.ipv.core.library.domain.Cri;
import uk.gov.di.ipv.core.library.domain.MitigationRoute;
import uk.gov.di.ipv.core.library.dto.CriConfig;
import uk.gov.di.ipv.core.library.dto.OauthCriConfig;
import uk.gov.di.ipv.core.library.dto.RestCriConfig;
import uk.gov.di.ipv.core.library.exceptions.ConfigException;
import uk.gov.di.ipv.core.library.exceptions.ConfigParameterNotFoundException;
import uk.gov.di.ipv.core.library.persistence.item.CriOAuthSessionItem;
import uk.org.webcompere.systemstubs.environment.EnvironmentVariables;
import uk.org.webcompere.systemstubs.jupiter.SystemStub;
import uk.org.webcompere.systemstubs.jupiter.SystemStubsExtension;
import uk.org.webcompere.systemstubs.properties.SystemProperties;

import java.net.URI;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.when;
import static org.mockito.quality.Strictness.LENIENT;
import static uk.gov.di.ipv.core.library.domain.Cri.ADDRESS;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.EC_PRIVATE_KEY_JWK;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.EC_PUBLIC_JWK_2;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.RSA_ENCRYPTION_PUBLIC_JWK;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.TEST_EC_PUBLIC_JWK;

@ExtendWith(MockitoExtension.class)
@ExtendWith(SystemStubsExtension.class)
class SsmConfigServiceYamlTest {

    public static final CriOAuthSessionItem CRI_OAUTH_SESSION_ITEM =
            CriOAuthSessionItem.builder().criId("ukPassport").connection("main").build();

    @SystemStub private EnvironmentVariables environmentVariables;

    @SystemStub private SystemProperties systemProperties;

    @Mock SSMProvider ssmProvider;

    @Mock SecretsProvider secretsProvider;

    private ConfigService configService;

    @BeforeEach
    void setUp() {
        configService = new SsmConfigService(ssmProvider, secretsProvider);
    }

    @Test
    void getParameterShouldGetParameterFromSsm() {
        var testComponentId = "test-component-id";
        environmentVariables.set("ENVIRONMENT", "test");
        when(ssmProvider.get("/test/core/self/componentId")).thenReturn(testComponentId);

        var value = configService.getParameter(ConfigurationVariable.COMPONENT_ID);

        assertEquals(testComponentId, value);
    }

    @Test
    void getParameterShouldThrowIfMissingInSsm() {
        environmentVariables.set("ENVIRONMENT", "test");
        when(ssmProvider.get("/test/core/self/componentId"))
                .thenThrow(ParameterNotFoundException.class);

        assertThrows(
                ConfigParameterNotFoundException.class,
                () -> configService.getParameter(ConfigurationVariable.COMPONENT_ID));
    }

    @Nested
    @DisplayName("active credential issuer config")
    class ActiveOauthCriConfig {

        private final Map<String, String> criStubConnection =
                Map.of(
                        "tokenUrl",
                        "https://testTokenUrl",
                        "credentialUrl",
                        "https://testCredentialUrl",
                        "authorizeUrl",
                        "https://testAuthoriseUrl",
                        "clientId",
                        "ipv-core-test",
                        "signingKey",
                        EC_PRIVATE_KEY_JWK,
                        "encryptionKey",
                        RSA_ENCRYPTION_PUBLIC_JWK,
                        "componentId",
                        "https://testComponentId",
                        "clientCallbackUrl",
                        "https://testClientCallBackUrl",
                        "requiresApiKey",
                        String.valueOf(true),
                        "jwksUrl",
                        "https://testWellKnownUrl");

        private final OauthCriConfig expectedOauthCriConfig =
                OauthCriConfig.builder()
                        .tokenUrl(URI.create("https://testTokenUrl"))
                        .credentialUrl(URI.create("https://testCredentialUrl"))
                        .authorizeUrl(URI.create("https://testAuthoriseUrl"))
                        .clientId("ipv-core-test")
                        .signingKey(EC_PRIVATE_KEY_JWK)
                        .encryptionKey(RSA_ENCRYPTION_PUBLIC_JWK)
                        .componentId("https://testComponentId")
                        .clientCallbackUrl(URI.create("https://testClientCallBackUrl"))
                        .requiresApiKey(true)
                        .requiresAdditionalEvidence(false)
                        .jwksUrl(URI.create("https://testWellKnownUrl"))
                        .build();

        @BeforeEach
        void setup() {
            when(ssmProvider.get("/test/core/self/configFormat")).thenReturn("yaml");
        }

        @Test
        void getOauthCriActiveConnectionConfigShouldGetCredentialIssuerFromParameterStore() {
            environmentVariables.set("ENVIRONMENT", "test");

            when(ssmProvider.get("/test/core/credentialIssuers/ukPassport/activeConnection"))
                    .thenReturn("stub");
            when(ssmProvider.getMultiple(
                            "/test/core/credentialIssuers/ukPassport/connections/stub"))
                    .thenReturn(criStubConnection);

            OauthCriConfig result = configService.getOauthCriActiveConnectionConfig(Cri.PASSPORT);

            assertEquals(expectedOauthCriConfig, result);
        }

        @Test
        void getOauthCriConfigShouldGetConfigForCriOauthSessionItem() {
            environmentVariables.set("ENVIRONMENT", "test");

            when(ssmProvider.getMultiple(
                            "/test/core/credentialIssuers/ukPassport/connections/stub"))
                    .thenReturn(criStubConnection);

            OauthCriConfig result =
                    configService.getOauthCriConfig(
                            CriOAuthSessionItem.builder()
                                    .criId(Cri.PASSPORT.getId())
                                    .connection("stub")
                                    .build());

            assertEquals(expectedOauthCriConfig, result);
        }

        @Test
        void getOauthCriConfigForConnectionShouldGetOauthCriConfig() {
            environmentVariables.set("ENVIRONMENT", "test");

            when(ssmProvider.getMultiple(
                            "/test/core/credentialIssuers/ukPassport/connections/stub"))
                    .thenReturn(criStubConnection);

            var result = configService.getOauthCriConfigForConnection("stub", Cri.PASSPORT);

            assertEquals(expectedOauthCriConfig, result);
        }

        @Test
        void getOauthCriConfigForConnectionShouldThrowIfNoCriConfigFound() {
            environmentVariables.set("ENVIRONMENT", "test");

            assertThrows(
                    ConfigParameterNotFoundException.class,
                    () -> configService.getOauthCriConfigForConnection("stub", Cri.PASSPORT));
        }

        @Test
        void getRestCriConfigShouldReturnARestCriConfig() throws Exception {
            environmentVariables.set("ENVIRONMENT", "test");

            when(ssmProvider.getMultiple("/test/core/credentialIssuers/address/connections/stub"))
                    .thenReturn(
                            Map.of(
                                    "credentialUrl",
                                    "https://testCredentialUrl",
                                    "signingKey",
                                    EC_PRIVATE_KEY_JWK,
                                    "componentId",
                                    "https://testComponentId",
                                    "requiresApiKey",
                                    "true"));

            RestCriConfig restCriConfig =
                    configService.getRestCriConfigForConnection("stub", ADDRESS);

            var expectedRestCriConfig =
                    RestCriConfig.builder()
                            .credentialUrl(new URI("https://testCredentialUrl"))
                            .requiresApiKey(true)
                            .signingKey(EC_PRIVATE_KEY_JWK)
                            .componentId("https://testComponentId")
                            .build();

            assertEquals(expectedRestCriConfig, restCriConfig);
        }

        @Test
        void getCriConfigShouldReturnACriConfig() {
            environmentVariables.set("ENVIRONMENT", "test");
            when(ssmProvider.get("/test/core/credentialIssuers/ukPassport/activeConnection"))
                    .thenReturn("stub");
            when(ssmProvider.getMultiple(
                            "/test/core/credentialIssuers/ukPassport/connections/stub"))
                    .thenReturn(
                            Map.of(
                                    "signingKey",
                                    EC_PRIVATE_KEY_JWK,
                                    "componentId",
                                    "https://testComponentId"));

            CriConfig criConfig = configService.getCriConfig(Cri.PASSPORT);

            var expectedCriConfig =
                    CriConfig.builder()
                            .signingKey(EC_PRIVATE_KEY_JWK)
                            .componentId("https://testComponentId")
                            .build();

            assertEquals(expectedCriConfig, criConfig);
        }
    }

    @Test
    void shouldReturnSlashSeparatedHistoricSigningKeys() {
        environmentVariables.set("ENVIRONMENT", "test");

        when(ssmProvider.get("/test/core/credentialIssuers/ukPassport/historicSigningKeys"))
                .thenReturn(String.format("%s/%s", TEST_EC_PUBLIC_JWK, EC_PUBLIC_JWK_2));

        var result = configService.getHistoricSigningKeys(Cri.PASSPORT.getId());

        assertEquals(TEST_EC_PUBLIC_JWK, result.get(0));
        assertEquals(EC_PUBLIC_JWK_2, result.get(1));
    }

    @ParameterizedTest
    @MethodSource("provideConfiguredSsmCimitConfig")
    void shouldFetchCimitConfig(Map<String, String> cimitData, String expectedDocument)
            throws ConfigException {
        environmentVariables.set("ENVIRONMENT", "test");

        when(ssmProvider.get("/test/core/self/configFormat")).thenReturn("yaml");

        when(ssmProvider.getMultiple("/test/core/cimit/config")).thenReturn(cimitData);
        Map<String, List<MitigationRoute>> expectedCimitConfig =
                Map.of(
                        "X01",
                        List.of(new MitigationRoute("/journey/do-a-thing", expectedDocument)));
        Map<String, List<MitigationRoute>> cimitConfig = configService.getCimitConfig();
        assertEquals(
                expectedCimitConfig.get("X01").get(0).event(),
                cimitConfig.get("X01").get(0).event());
        assertEquals(
                expectedCimitConfig.get("X01").get(0).document(),
                cimitConfig.get("X01").get(0).document());
    }

    private static Stream<Arguments> provideConfiguredSsmCimitConfig() {
        return Stream.of(
                Arguments.of(Map.of("X01", "[{\"event\": \"/journey/do-a-thing\"}]"), null),
                Arguments.of(
                        Map.of(
                                "X01",
                                "[{\"event\": \"/journey/do-a-thing\", \"document\": \"drivingPermit\"}]"),
                        "drivingPermit"));
    }

    @Test
    void shouldThrowErrorOnInvalidCimitConfig() {
        environmentVariables.set("ENVIRONMENT", "test");

        when(ssmProvider.get("/test/core/self/configFormat")).thenReturn("yaml");

        when(ssmProvider.getMultiple("/test/core/cimit/config"))
                .thenReturn(Map.of("/test/core/cimit/config/restOfPath", "}"));

        assertThrows(ConfigException.class, () -> configService.getCimitConfig());
    }

    @Nested
    @MockitoSettings(strictness = LENIENT)
    class GetCriByIssuerTests {
        @BeforeEach
        void setup() {
            environmentVariables.set("ENVIRONMENT", "test");

            when(ssmProvider.get("/test/core/self/configFormat")).thenReturn("yaml");

            when(ssmProvider.get("/test/core/credentialIssuers/address/activeConnection"))
                    .thenReturn("stub");
            when(ssmProvider.get("/test/core/credentialIssuers/address/connections/stub"))
                    .thenThrow(ParameterNotFoundException.class);

            when(ssmProvider.get(
                            "/test/core/credentialIssuers/address/connections/stub/componentId"))
                    .thenThrow(ConfigParameterNotFoundException.class);

            when(ssmProvider.get("/test/core/credentialIssuers/bav/activeConnection"))
                    .thenReturn("stub");
            when(ssmProvider.get("/test/core/credentialIssuers/bav/connections/stub/componentId"))
                    .thenReturn("https://stub-bav-component-id");

            when(ssmProvider.get("/test/core/credentialIssuers/dcmaw/activeConnection"))
                    .thenReturn("stub");
            when(ssmProvider.get("/test/core/credentialIssuers/dcmaw/connections/stub/componentId"))
                    .thenReturn("https://stub-dcmaw-component-id");

            when(ssmProvider.get("/test/core/credentialIssuers/cimit/activeConnection"))
                    .thenThrow(ConfigParameterNotFoundException.class);
            when(ssmProvider.get("/test/core/credentialIssuers/cimit/connections/stub/componentId"))
                    .thenThrow(ConfigParameterNotFoundException.class);

            when(ssmProvider.get("/test/core/credentialIssuers/claimedIdentity/activeConnection"))
                    .thenThrow(ConfigParameterNotFoundException.class);
            when(ssmProvider.get(
                            "/test/core/credentialIssuers/claimedIdentity/connections/stub/componentId"))
                    .thenThrow(ConfigParameterNotFoundException.class);

            when(ssmProvider.get("/test/core/credentialIssuers/dcmawAsync/activeConnection"))
                    .thenThrow(ConfigParameterNotFoundException.class);
            when(ssmProvider.get(
                            "/test/core/credentialIssuers/dcmawAsync/connections/stub/componentId"))
                    .thenThrow(ConfigParameterNotFoundException.class);

            when(ssmProvider.get("/test/core/credentialIssuers/drivingLicence/activeConnection"))
                    .thenThrow(ConfigParameterNotFoundException.class);
            when(ssmProvider.get(
                            "/test/core/credentialIssuers/drivingLicence/connections/stub/componentId"))
                    .thenThrow(ConfigParameterNotFoundException.class);

            when(ssmProvider.get("/test/core/credentialIssuers/dwpKbv/activeConnection"))
                    .thenThrow(ConfigParameterNotFoundException.class);
            when(ssmProvider.get(
                            "/test/core/credentialIssuers/dwpKbv/connections/stub/componentId"))
                    .thenThrow(ConfigParameterNotFoundException.class);

            when(ssmProvider.get("/test/core/credentialIssuers/fraud/activeConnection"))
                    .thenThrow(ConfigParameterNotFoundException.class);
            when(ssmProvider.get("/test/core/credentialIssuers/fraud/connections/stub/componentId"))
                    .thenThrow(ConfigParameterNotFoundException.class);

            when(ssmProvider.get("/test/core/credentialIssuers/experianKbv/activeConnection"))
                    .thenThrow(ConfigParameterNotFoundException.class);
            when(ssmProvider.get(
                            "/test/core/credentialIssuers/experianKbv/connections/stub/componentId"))
                    .thenThrow(ConfigParameterNotFoundException.class);

            when(ssmProvider.get("/test/core/credentialIssuers/f2f/activeConnection"))
                    .thenThrow(ConfigParameterNotFoundException.class);
            when(ssmProvider.get("/test/core/credentialIssuers/f2f/connections/stub/componentId"))
                    .thenThrow(ConfigParameterNotFoundException.class);

            when(ssmProvider.get("/test/core/credentialIssuers/hmrcMigration/activeConnection"))
                    .thenThrow(ConfigParameterNotFoundException.class);
            when(ssmProvider.get(
                            "/test/core/credentialIssuers/hmrcMigration/connections/stub/componentId"))
                    .thenThrow(ConfigParameterNotFoundException.class);

            when(ssmProvider.get("/test/core/credentialIssuers/nino/activeConnection"))
                    .thenThrow(ConfigParameterNotFoundException.class);
            when(ssmProvider.get("/test/core/credentialIssuers/nino/connections/stub/componentId"))
                    .thenThrow(ConfigParameterNotFoundException.class);

            when(ssmProvider.get("/test/core/credentialIssuers/ukPassport/activeConnection"))
                    .thenThrow(ConfigParameterNotFoundException.class);
            when(ssmProvider.get(
                            "/test/core/credentialIssuers/ukPassport/connections/stub/componentId"))
                    .thenThrow(ConfigParameterNotFoundException.class);

            when(ssmProvider.get("/test/core/credentialIssuers/ticf/activeConnection"))
                    .thenThrow(ConfigParameterNotFoundException.class);
            when(ssmProvider.get("/test/core/credentialIssuers/ticf/connections/stub/componentId"))
                    .thenThrow(ConfigParameterNotFoundException.class);
        }

        @Test
        void shouldReturnCriForValidIssuers() {
            assertEquals(
                    Map.of(
                            "https://stub-dcmaw-component-id",
                            Cri.DCMAW,
                            "https://stub-bav-component-id",
                            Cri.BAV),
                    configService.getIssuerCris());
        }
    }
}
