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
    private static final String TEST_CERT =
            "MIIC/TCCAeWgAwIBAgIBATANBgkqhkiG9w0BAQsFADAsMR0wGwYDVQQDDBRjcmktdWstcGFzc3BvcnQtYmFjazELMAkGA1UEBhMCR0IwHhcNMjExMjE3MTEwNTM5WhcNMjIxMjE3MTEwNTM5WjAsMR0wGwYDVQQDDBRjcmktdWstcGFzc3BvcnQtYmFjazELMAkGA1UEBhMCR0IwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDYIxWKwYNoz2MIDvYb2ip4nhCOGUccufIqwSHXl5FBOoOxOZh1rV57sWhdKO/hyZYbF5YUYTwzV4rW7DgLkfx0sN/p5igk74BZRSXvV/s+XCkVC5c0NDhNGh6WK5rc8Qbm0Ad5vEO1JpQih5y2mPGCwfLBqcY8AC7fwZinP/4YoMTCtEk5ueA0HwZLHXOEMWl/QCkj7WlSBL4i6ozk4So3RFL4awYP6nvhY7OLAcad7g/ZW0dXvztPOJnT9rwi1p6BNoD/Zk6jMJHhbvKyGsluUy7PYVGYCQ36Uuzby2Jq8cG5qNS+CBjy0/d/RmrClKd7gcnLY/J5NOC+YSynoHXRAgMBAAGjKjAoMA4GA1UdDwEB/wQEAwIFoDAWBgNVHSUBAf8EDDAKBggrBgEFBQcDBDANBgkqhkiG9w0BAQsFAAOCAQEAvHT2AGTymh02A9HWrnGm6PEXx2Ye3NXV9eJNU1z6J298mS2kYq0Z4D0hj9i8+IoCQRbWOxLTAWBNt/CmH7jWltE4uqoAwTZD6mDgkC2eo5dY+RcuydsvJNfTcvUOyi47KKGGEcddfLti4NuX51BQIY5vSBfqZXt8+y28WuWqBMh6eny2wJtxNHo20wQei5g7w19lqwJu2F+l/ykX9K5DHjhXqZUJ77YWmY8sy/WROLjOoZZRy6YuzV8S/+c/nsPzqDAkD4rpWwASjsEDaTcH22xpGq5XUAf1hwwNsuiyXKGUHCxafYYS781LR8pLg6DpEAgcn8tBbq6MoiEGVeOp7Q=="; // pragma: allowlist secret
    private static final String TEST_CERT_FS01 = "not a real cert";

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
            when(ssmProvider.getMultiple("/test/core/credentialIssuers"))
                    .thenReturn(
                            Map.of(
                                    "ticf/connections/stub/componentId",
                                    "https://stub-ticf-component-id",
                                    "ticf/connections/main/componentId",
                                    "https://main-ticf-component-id",
                                    "dcmaw/connections/stub/componentId",
                                    "https://stub-dcmaw-component-id",
                                    "dcmaw/connections/main/componentId",
                                    "https://main-dcmaw-component-id"));
        }

        @Test
        void shouldReturnCriForValidIssuers() {
            assertEquals(
                    Map.of(
                            "https://main-ticf-component-id",
                            Cri.TICF,
                            "https://stub-ticf-component-id",
                            Cri.TICF,
                            "https://main-dcmaw-component-id",
                            Cri.DCMAW,
                            "https://stub-dcmaw-component-id",
                            Cri.DCMAW),
                    configService.getIssuerCris());
        }
    }
}
