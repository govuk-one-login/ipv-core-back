package uk.gov.di.ipv.core.library.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.tomakehurst.wiremock.junit5.WireMockRuntimeInfo;
import com.github.tomakehurst.wiremock.junit5.WireMockTest;
import com.google.gson.Gson;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import software.amazon.awssdk.services.secretsmanager.model.DecryptionFailureException;
import software.amazon.awssdk.services.secretsmanager.model.InternalServiceErrorException;
import software.amazon.awssdk.services.secretsmanager.model.InvalidParameterException;
import software.amazon.awssdk.services.secretsmanager.model.InvalidRequestException;
import software.amazon.awssdk.services.secretsmanager.model.ResourceNotFoundException;
import software.amazon.lambda.powertools.parameters.SSMProvider;
import software.amazon.lambda.powertools.parameters.SecretsProvider;
import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
import uk.gov.di.ipv.core.library.config.FeatureFlag;
import uk.gov.di.ipv.core.library.domain.ContraIndicatorMitigation;
import uk.gov.di.ipv.core.library.domain.ContraIndicatorScore;
import uk.gov.di.ipv.core.library.dto.CredentialIssuerConfig;
import uk.gov.di.ipv.core.library.exceptions.ConfigException;
import uk.org.webcompere.systemstubs.environment.EnvironmentVariables;
import uk.org.webcompere.systemstubs.jupiter.SystemStub;
import uk.org.webcompere.systemstubs.jupiter.SystemStubsExtension;
import uk.org.webcompere.systemstubs.properties.SystemProperties;

import java.net.URI;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static com.github.tomakehurst.wiremock.client.WireMock.getAllServeEvents;
import static com.github.tomakehurst.wiremock.client.WireMock.ok;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.stubFor;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.EC_PRIVATE_KEY_JWK;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.RSA_ENCRYPTION_PUBLIC_JWK;

@WireMockTest(httpPort = ConfigService.LOCALHOST_PORT)
@ExtendWith(MockitoExtension.class)
@ExtendWith(SystemStubsExtension.class)
class ConfigServiceTest {

    private static final String TEST_CERT =
            "MIIC/TCCAeWgAwIBAgIBATANBgkqhkiG9w0BAQsFADAsMR0wGwYDVQQDDBRjcmktdWstcGFzc3BvcnQtYmFjazELMAkGA1UEBhMCR0IwHhcNMjExMjE3MTEwNTM5WhcNMjIxMjE3MTEwNTM5WjAsMR0wGwYDVQQDDBRjcmktdWstcGFzc3BvcnQtYmFjazELMAkGA1UEBhMCR0IwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDYIxWKwYNoz2MIDvYb2ip4nhCOGUccufIqwSHXl5FBOoOxOZh1rV57sWhdKO/hyZYbF5YUYTwzV4rW7DgLkfx0sN/p5igk74BZRSXvV/s+XCkVC5c0NDhNGh6WK5rc8Qbm0Ad5vEO1JpQih5y2mPGCwfLBqcY8AC7fwZinP/4YoMTCtEk5ueA0HwZLHXOEMWl/QCkj7WlSBL4i6ozk4So3RFL4awYP6nvhY7OLAcad7g/ZW0dXvztPOJnT9rwi1p6BNoD/Zk6jMJHhbvKyGsluUy7PYVGYCQ36Uuzby2Jq8cG5qNS+CBjy0/d/RmrClKd7gcnLY/J5NOC+YSynoHXRAgMBAAGjKjAoMA4GA1UdDwEB/wQEAwIFoDAWBgNVHSUBAf8EDDAKBggrBgEFBQcDBDANBgkqhkiG9w0BAQsFAAOCAQEAvHT2AGTymh02A9HWrnGm6PEXx2Ye3NXV9eJNU1z6J298mS2kYq0Z4D0hj9i8+IoCQRbWOxLTAWBNt/CmH7jWltE4uqoAwTZD6mDgkC2eo5dY+RcuydsvJNfTcvUOyi47KKGGEcddfLti4NuX51BQIY5vSBfqZXt8+y28WuWqBMh6eny2wJtxNHo20wQei5g7w19lqwJu2F+l/ykX9K5DHjhXqZUJ77YWmY8sy/WROLjOoZZRy6YuzV8S/+c/nsPzqDAkD4rpWwASjsEDaTcH22xpGq5XUAf1hwwNsuiyXKGUHCxafYYS781LR8pLg6DpEAgcn8tBbq6MoiEGVeOp7Q==";
    private static final String TEST_CERT_FS01 = "not a real cert";

    @SystemStub private EnvironmentVariables environmentVariables;

    @SystemStub private SystemProperties systemProperties;

    @Mock SSMProvider ssmProvider;

    @Mock SecretsProvider secretsProvider;

    private ConfigService configService;

    private final Gson gson = new Gson();

    @BeforeEach
    void setUp() {
        configService = new ConfigService(ssmProvider, secretsProvider);
    }

    @Test
    void usesLocalSSMProviderWhenRunningLocally(WireMockRuntimeInfo wmRuntimeInfo)
            throws JsonProcessingException {
        stubFor(post("/").willReturn(ok()));
        environmentVariables.set("IS_LOCAL", "true");
        environmentVariables.set("AWS_ACCESS_KEY_ID", "ASDFGHJKL");
        environmentVariables.set("AWS_SECRET_ACCESS_KEY", "1234567890987654321");

        systemProperties.set(
                "software.amazon.awssdk.http.service.impl",
                "software.amazon.awssdk.http.urlconnection.UrlConnectionSdkHttpService");

        SSMProvider ssmProvider = new ConfigService().getSsmProvider();
        assertThrows(NullPointerException.class, () -> ssmProvider.get("any-old-thing"));

        HashMap requestBody =
                new ObjectMapper()
                        .readValue(
                                getAllServeEvents().get(0).getRequest().getBodyAsString(),
                                HashMap.class);

        assertEquals("any-old-thing", requestBody.get("Name"));
        assertEquals(false, requestBody.get("WithDecryption"));
    }

    @Nested
    @DisplayName("active credential issuer config")
    class ActiveCredentialIssuerConfig {

        private final Map<String, String> baseCredentialIssuerConfig =
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
                        "true");

        private final CredentialIssuerConfig expectedBaseCredentialIssuerConfig =
                new CredentialIssuerConfig(
                        URI.create("https://testTokenUrl"),
                        URI.create("https://testCredentialUrl"),
                        URI.create("https://testAuthoriseUrl"),
                        "ipv-core-test",
                        EC_PRIVATE_KEY_JWK,
                        RSA_ENCRYPTION_PUBLIC_JWK,
                        "https://testComponentId",
                        URI.create("https://testClientCallBackUrl"),
                        true);

        private final Map<String, String> featureSetCredentialIssuerConfig =
                Map.of(
                        "tokenUrl", "https://testTokenUrl_for_fs01",
                        "clientId", "client_for_fs01",
                        "requiresApiKey", "false");

        private final CredentialIssuerConfig expectedFeatureSetCredentialIssuerConfig =
                new CredentialIssuerConfig(
                        URI.create("https://testTokenUrl_for_fs01"),
                        URI.create("https://testCredentialUrl"),
                        URI.create("https://testAuthoriseUrl"),
                        "client_for_fs01",
                        EC_PRIVATE_KEY_JWK,
                        RSA_ENCRYPTION_PUBLIC_JWK,
                        "https://testComponentId",
                        URI.create("https://testClientCallBackUrl"),
                        false);

        private void checkCredentialIssuerConfig(
                CredentialIssuerConfig expected, CredentialIssuerConfig actual) {
            // CredentialIssuerConfig equality currently checks only clientId, tokenUrl, and
            // credentialUrl
            assertEquals(expected, actual);
            assertEquals(expected.getAuthorizeUrl(), actual.getAuthorizeUrl());
            assertEquals(expected.getSigningKeyString(), actual.getSigningKeyString());
            assertEquals(expected.getEncryptionKeyString(), actual.getEncryptionKeyString());
            assertEquals(expected.getComponentId(), actual.getComponentId());
            assertEquals(expected.getClientCallbackUrl(), actual.getClientCallbackUrl());
            assertEquals(expected.getRequiresApiKey(), actual.getRequiresApiKey());
        }

        @Test
        void shouldGetCredentialIssuerFromParameterStore() {
            environmentVariables.set("ENVIRONMENT", "test");

            when(ssmProvider.get("/test/core/credentialIssuers/passportCri/activeConnection"))
                    .thenReturn("stub");
            when(ssmProvider.getMultiple(
                            "/test/core/credentialIssuers/passportCri/connections/stub"))
                    .thenReturn(baseCredentialIssuerConfig);

            CredentialIssuerConfig result =
                    configService.getCredentialIssuerActiveConnectionConfig("passportCri");

            checkCredentialIssuerConfig(expectedBaseCredentialIssuerConfig, result);
        }

        @Test
        void shouldApplyFeatureSetOverridesOnActiveConfiguration() {
            environmentVariables.set("ENVIRONMENT", "test");
            configService.setFeatureSet("fs01");

            when(ssmProvider.get("/test/core/credentialIssuers/passportCri/activeConnection"))
                    .thenReturn("stub");
            when(ssmProvider.getMultiple("/test/core/features/fs01/credentialIssuers/passportCri"))
                    .thenReturn(Map.of());
            when(ssmProvider.getMultiple(
                            "/test/core/credentialIssuers/passportCri/connections/stub"))
                    .thenReturn(baseCredentialIssuerConfig);
            when(ssmProvider.getMultiple(
                            "/test/core/features/fs01/credentialIssuers/passportCri/connections/stub"))
                    .thenReturn(featureSetCredentialIssuerConfig);

            CredentialIssuerConfig result =
                    configService.getCredentialIssuerActiveConnectionConfig("passportCri");

            checkCredentialIssuerConfig(expectedFeatureSetCredentialIssuerConfig, result);
        }

        @Test
        void shouldOverrideActiveConfigurationForAFeatureSet() {
            environmentVariables.set("ENVIRONMENT", "test");
            configService.setFeatureSet("fs01");

            when(ssmProvider.getMultiple("/test/core/features/fs01/credentialIssuers/passportCri"))
                    .thenReturn(Map.of("activeConnection", "main"));
            when(ssmProvider.getMultiple(
                            "/test/core/credentialIssuers/passportCri/connections/main"))
                    .thenReturn(baseCredentialIssuerConfig);

            CredentialIssuerConfig result =
                    configService.getCredentialIssuerActiveConnectionConfig("passportCri");

            checkCredentialIssuerConfig(expectedBaseCredentialIssuerConfig, result);
        }

        @Test
        void shouldApplyFeatureSetOverridesOnFeatureSetActiveConfiguration() {
            environmentVariables.set("ENVIRONMENT", "test");
            configService.setFeatureSet("fs01");

            when(ssmProvider.getMultiple("/test/core/features/fs01/credentialIssuers/passportCri"))
                    .thenReturn(Map.of("activeConnection", "main"));
            when(ssmProvider.getMultiple(
                            "/test/core/credentialIssuers/passportCri/connections/main"))
                    .thenReturn(baseCredentialIssuerConfig);
            when(ssmProvider.getMultiple(
                            "/test/core/features/fs01/credentialIssuers/passportCri/connections/main"))
                    .thenReturn(featureSetCredentialIssuerConfig);

            CredentialIssuerConfig result =
                    configService.getCredentialIssuerActiveConnectionConfig("passportCri");

            checkCredentialIssuerConfig(expectedFeatureSetCredentialIssuerConfig, result);
        }

        @Test
        void shouldGetComponentIdForActiveConnection() {
            environmentVariables.set("ENVIRONMENT", "test");
            final String testCredentialIssuerId = "address";
            final String testComponentId = "testComponentId";
            when(ssmProvider.get("/test/core/credentialIssuers/address/activeConnection"))
                    .thenReturn("stub");
            when(ssmProvider.get(
                            "/test/core/credentialIssuers/address/connections/stub/componentId"))
                    .thenReturn(testComponentId);
            assertEquals(testComponentId, configService.getComponentId(testCredentialIssuerId));
        }

        @Test
        void shouldLookForFeatureSetOverrideOfComponentIdOnActiveConfiguration() {
            environmentVariables.set("ENVIRONMENT", "test");
            configService.setFeatureSet("fs01");
            final String testCredentialIssuerId = "address";
            final String testComponentId = "testComponentId";

            when(ssmProvider.get("/test/core/credentialIssuers/address/activeConnection"))
                    .thenReturn("stub");
            when(ssmProvider.getMultiple("/test/core/features/fs01/credentialIssuers/address"))
                    .thenReturn(Map.of());
            when(ssmProvider.get(
                            "/test/core/credentialIssuers/address/connections/stub/componentId"))
                    .thenReturn(testComponentId);
            when(ssmProvider.getMultiple(
                            "/test/core/features/fs01/credentialIssuers/address/connections/stub"))
                    .thenReturn(Map.of());
            assertEquals(testComponentId, configService.getComponentId(testCredentialIssuerId));
        }

        @Test
        void shouldApplyFeatureSetOverrideOfComponentIdOnActiveConfiguration() {
            environmentVariables.set("ENVIRONMENT", "test");
            configService.setFeatureSet("fs01");
            final String testCredentialIssuerId = "address";
            final String testComponentId = "testComponentId";

            when(ssmProvider.get("/test/core/credentialIssuers/address/activeConnection"))
                    .thenReturn("stub");
            when(ssmProvider.getMultiple("/test/core/features/fs01/credentialIssuers/address"))
                    .thenReturn(Map.of());
            when(ssmProvider.getMultiple(
                            "/test/core/features/fs01/credentialIssuers/address/connections/stub"))
                    .thenReturn(Map.of("componentId", "testComponentId"));
            assertEquals(testComponentId, configService.getComponentId(testCredentialIssuerId));
        }
    }

    @ParameterizedTest
    @CsvSource({",", "' ',", "' \t\n',", "fs0001,fs0001"})
    void shouldNormaliseNullAndEmptyFeatureSetsToNull(
            String featureSet, String expectedFeatureSet) {
        configService.setFeatureSet(featureSet);
        assertEquals(expectedFeatureSet, configService.getFeatureSet());
    }

    @Nested
    @DisplayName("credential issuer config items")
    class CredentialIssuerConfigItems {

        private void setupTestData(
                String credentialIssuer,
                String attributeName,
                String baseValue,
                String featureSet,
                String featureSetValue) {
            environmentVariables.set("ENVIRONMENT", "test");
            configService.setFeatureSet(featureSet);
            if (featureSet == null) {
                when(ssmProvider.get(
                                String.format(
                                        "/test/core/credentialIssuers/%s/%s",
                                        credentialIssuer, attributeName)))
                        .thenReturn(baseValue);
            } else {
                when(ssmProvider.getMultiple(
                                String.format(
                                        "/test/core/features/%s/credentialIssuers/%s",
                                        featureSet, credentialIssuer)))
                        .thenReturn(Map.of(attributeName, featureSetValue));
            }
        }

        @ParameterizedTest
        @CsvSource({"main,stub,,main", "main,stub,fs01,stub"})
        void shouldGetActiveConnection(
                String baseActiveConnection,
                String featureSetActiveConnection,
                String featureSet,
                String expectedActiveConnection) {
            final String credentialIssuer = "passportCri";
            setupTestData(
                    credentialIssuer,
                    "activeConnection",
                    baseActiveConnection,
                    featureSet,
                    featureSetActiveConnection);
            assertEquals(
                    expectedActiveConnection, configService.getActiveConnection(credentialIssuer));
        }

        @ParameterizedTest
        @CsvSource({"true,false,,true", "true,false,fs01,false"})
        void shouldReturnIsEnabled(
                String baseIsEnabled,
                String featureSetIsEnabled,
                String featureSet,
                String expectedIsEnabled) {
            final String credentialIssuer = "passportCri";
            setupTestData(
                    credentialIssuer, "enabled", baseIsEnabled, featureSet, featureSetIsEnabled);
            assertEquals(
                    Boolean.parseBoolean(expectedIsEnabled),
                    configService.isEnabled(credentialIssuer));
        }

        @ParameterizedTest
        @CsvSource({"false,true,,false", "false,true,fs01,true"})
        void shouldReturnIsUnavailableOrNot(
                String baseIsUnavailable,
                String featureSetIsUnavailable,
                String featureSet,
                String expectedIsUnavailable) {
            final String credentialIssuer = "passportCri";
            setupTestData(
                    credentialIssuer,
                    "unavailable",
                    baseIsUnavailable,
                    featureSet,
                    featureSetIsUnavailable);
            assertEquals(
                    Boolean.parseBoolean(expectedIsUnavailable),
                    configService.isUnavailable(credentialIssuer));
        }

        @ParameterizedTest
        @CsvSource(
                delimiter = '|',
                value = {
                    "address,name|address,name,dob||address,name",
                    "address,name|address,name,dob|fs01|address,name,dob"
                })
        void shouldReturnAllowedSharedAttributes(
                String baseAllowedSharedAttributes,
                String featureSetAllowedSharedAttributes,
                String featureSet,
                String expectedIAllowedSharedAttributes) {
            final String credentialIssuer = "passportCri";
            setupTestData(
                    credentialIssuer,
                    "allowedSharedAttributes",
                    baseAllowedSharedAttributes,
                    featureSet,
                    featureSetAllowedSharedAttributes);
            assertEquals(
                    expectedIAllowedSharedAttributes,
                    configService.getAllowedSharedAttributes(credentialIssuer));
        }
    }

    @ParameterizedTest
    @CsvSource({
        "CLIENT_VALID_REDIRECT_URLS,",
        "CLIENT_VALID_REDIRECT_URLS,FS05",
        "CLIENT_VALID_REDIRECT_URLS,FS06_NO_OVERRIDE"
    })
    void shouldReturnListOfClientRedirectUrls(String testDataSet, String featureSet) {
        environmentVariables.set("ENVIRONMENT", "test");
        configService.setFeatureSet(featureSet);
        TestConfiguration testConfiguration = TestConfiguration.valueOf(testDataSet);
        testConfiguration.setupMockConfig(ssmProvider);
        assertEquals(
                Arrays.asList(testConfiguration.getExpectedValue(featureSet).split(",")),
                configService.getClientRedirectUrls("aClientId"));
    }

    @ParameterizedTest
    @CsvSource({"FEATURE_FLAGS,", "FEATURE_FLAGS,FS07"})
    void shouldGetNamedFeatureFlag(String testDataSet, String featureSet) {
        environmentVariables.set("ENVIRONMENT", "test");
        configService.setFeatureSet(featureSet);
        TestConfiguration testConfiguration = TestConfiguration.valueOf(testDataSet);
        testConfiguration.setupMockConfig(ssmProvider);
        assertEquals(
                Boolean.parseBoolean(testConfiguration.getExpectedValue(featureSet)),
                configService.enabled(TestFeatureFlag.TEST_FEATURE));
    }

    @Test
    void shouldGetSecretValueFromSecretsManager() {
        Map<String, String> apiKeySecret = Map.of("apiKey", "api-key-value");
        when(secretsProvider.get(any())).thenReturn(gson.toJson(apiKeySecret));

        String apiKey = configService.getCriPrivateApiKey("ukPassport");

        assertEquals("api-key-value", apiKey);
    }

    @Test
    void shouldReturnNullOnDecryptionFailureFromSecretsManager() {
        DecryptionFailureException decryptionFailureException =
                DecryptionFailureException.builder().message("Test decryption error").build();
        when(secretsProvider.get(any())).thenThrow(decryptionFailureException);

        String apiKey = configService.getCriPrivateApiKey("ukPassport");

        assertNull(apiKey);
    }

    @Test
    void shouldReturnNullOnInternalServiceErrorExceptionFromSecretsManager() {
        InternalServiceErrorException internalServiceErrorException =
                InternalServiceErrorException.builder()
                        .message("Test internal service error")
                        .build();
        when(secretsProvider.get(any())).thenThrow(internalServiceErrorException);

        String apiKey = configService.getCriPrivateApiKey("ukPassport");

        assertNull(apiKey);
    }

    @Test
    void shouldReturnNullOnInvalidParameterExceptionFromSecretsManager() {
        InvalidParameterException invalidParameterException =
                InvalidParameterException.builder().message("Test invalid parameter error").build();
        when(secretsProvider.get(any())).thenThrow(invalidParameterException);

        String apiKey = configService.getCriPrivateApiKey("ukPassport");

        assertNull(apiKey);
    }

    @Test
    void shouldReturnNullOnInvalidRequestExceptionFromSecretsManager() {
        InvalidRequestException invalidRequestException =
                InvalidRequestException.builder().message("Test invalid request error").build();
        when(secretsProvider.get(any())).thenThrow(invalidRequestException);

        String apiKey = configService.getCriPrivateApiKey("ukPassport");

        assertNull(apiKey);
    }

    @Test
    void shouldReturnNullOnResourceNotFoundExceptionFromSecretsManager() {
        ResourceNotFoundException resourceNotFoundException =
                ResourceNotFoundException.builder()
                        .message("Test resource not found error")
                        .build();
        when(secretsProvider.get(any())).thenThrow(resourceNotFoundException);

        String apiKey = configService.getCriPrivateApiKey("ukPassport");

        assertNull(apiKey);
    }

    @Test
    void shouldReturnNullOnInvalidApiKeyJsonFromSecretsManager() {
        when(secretsProvider.get(any())).thenReturn("{\"apiKey\":\"invalidJson}");
        String apiKey = configService.getCriPrivateApiKey("ukPassport");
        assertNull(apiKey);
    }

    @Test
    void shouldGetContraIndicatorScoresMap() {
        String scoresJsonString =
                "[{ \"ci\": \"X01\", \"detectedScore\": 3, \"checkedScore\": -3, \"fidCode\": \"YZ01\" }, { \"ci\": \"Z03\", \"detectedScore\": 5, \"checkedScore\": -3 }]";
        when(secretsProvider.get(any())).thenReturn(scoresJsonString);

        Map<String, ContraIndicatorScore> scoresMap = configService.getContraIndicatorScoresMap();

        assertEquals(2, scoresMap.size());
        assertTrue(scoresMap.containsKey("X01"));
        assertTrue(scoresMap.containsKey("Z03"));
    }

    @Test
    void shouldReturnEmptyCollectionOnInvalidContraIndicatorScoresMap() {
        final String invalidCIScoresJsonString =
                "[\"ci\":\"X01\",\"detectedScore\":3,\"checkedScore\":-3,\"fidCode\":\"YZ01\"}]";
        when(secretsProvider.get(any())).thenReturn(invalidCIScoresJsonString);
        Map<String, ContraIndicatorScore> scoresMap = configService.getContraIndicatorScoresMap();
        assertTrue(scoresMap.isEmpty());
    }

    @Test
    void shouldGetBearerAccessTokenTtlFromEnvironmentVariableIfSet() {
        environmentVariables.set("BEARER_TOKEN_TTL", "1800");
        assertEquals(1800L, configService.getBearerAccessTokenTtl());
    }

    @Test
    void shouldDefaultBearerAccessTokenTtlIfEnvironmentVariableNotSet() {
        assertEquals(3600L, configService.getBearerAccessTokenTtl());
    }

    @Test
    void shouldGetSigningKeyIdParamNamedByEnvironmentVariable() {
        final String signingKeyIdPath = "/test/core/self/signingKeyId";
        final String testSigningKeyId = "6CA2A18E-AFAD-41B4-95EC-53F967A290BE";
        environmentVariables.set("SIGNING_KEY_ID_PARAM", signingKeyIdPath);
        when(ssmProvider.get(signingKeyIdPath)).thenReturn(testSigningKeyId);
        assertEquals(testSigningKeyId, configService.getSigningKeyId());
    }

    @ParameterizedTest
    @CsvSource({
        "PUBLIC_KEY_MATERIAL_FOR_CORE_TO_VERIFY,",
        "PUBLIC_KEY_MATERIAL_FOR_CORE_TO_VERIFY,FS01",
        "CLIENT_ISSUER,",
        "CLIENT_ISSUER,FS02",
        "CLIENT_ISSUER,FS03_NO_OVERRIDE"
    })
    void shouldAccountForFeatureSetWhenRetrievingParameterForClient(
            String configVariableName, String featureSet) {
        configService = new ConfigService(ssmProvider, secretsProvider, featureSet);
        environmentVariables.set("ENVIRONMENT", "test");
        ConfigurationVariable configurationVariable =
                ConfigurationVariable.valueOf(configVariableName);
        TestConfiguration testConfiguration = TestConfiguration.valueOf(configVariableName);
        testConfiguration.setupMockConfig(ssmProvider);
        assertEquals(
                testConfiguration.getExpectedValue(featureSet),
                configService.getSsmParameter(configurationVariable, "aClientId"));
    }

    @ParameterizedTest
    @CsvSource({
        "MAX_ALLOWED_AUTH_CLIENT_TTL,",
        "MAX_ALLOWED_AUTH_CLIENT_TTL,FS01",
        "CORE_FRONT_CALLBACK_URL,",
        "CORE_FRONT_CALLBACK_URL,FS01",
        "CORE_VTM_CLAIM,",
        "CORE_VTM_CLAIM,FS02",
        "BACKEND_SESSION_TIMEOUT,",
        "BACKEND_SESSION_TIMEOUT,FS03",
        "BACKEND_SESSION_TTL,",
        "BACKEND_SESSION_TTL,FS04",
        "BACKEND_SESSION_TTL,FS05_NO_OVERRIDE",
    })
    void shouldAccountForFeatureSetWhenRetrievingParameter(
            String configVariableName, String featureSet) {
        configService = new ConfigService(ssmProvider, secretsProvider, featureSet);
        environmentVariables.set("ENVIRONMENT", "test");
        ConfigurationVariable configurationVariable =
                ConfigurationVariable.valueOf(configVariableName);
        TestConfiguration testConfiguration = TestConfiguration.valueOf(configVariableName);
        testConfiguration.setupMockConfig(ssmProvider);
        assertEquals(
                testConfiguration.getExpectedValue(featureSet),
                configService.getSsmParameter(configurationVariable));
    }

    private enum TestConfiguration {
        PUBLIC_KEY_MATERIAL_FOR_CORE_TO_VERIFY(
                "clients/aClientId/publicKeyMaterialForCoreToVerify",
                TEST_CERT,
                Map.of("FS01", TEST_CERT_FS01)),
        CLIENT_ISSUER(
                "clients/aClientId/issuer", "aClientIssuer", Map.of("FS02", "aDifferentIssuer")),
        MAX_ALLOWED_AUTH_CLIENT_TTL(
                "self/maxAllowedAuthClientTtl",
                "aClientTokenTtl",
                Map.of("FS01", "aDifferentClientTokenTtl")),
        CORE_FRONT_CALLBACK_URL(
                "self/coreFrontCallbackUrl",
                "aCoreFrontCallbackUrl",
                Map.of("FS01", "aDifferentCoreFrontCallbackUrl")),
        CORE_VTM_CLAIM(
                "self/coreVtmClaim", "aCoreVtmClaim", Map.of("FS02", "aDifferentCoreVtmClaim")),
        BACKEND_SESSION_TIMEOUT(
                "self/backendSessionTimeout", "7200", Map.of("FS02", "7300", "FS03", "7400")),
        BACKEND_SESSION_TTL(
                "self/backendSessionTtl", "3600", Map.of("FS03", "3700", "FS04", "3800")),
        CLIENT_VALID_REDIRECT_URLS(
                "clients/aClientId/validRedirectUrls",
                "one.example.com/callback,two.example.com/callback,three.example.com/callback",
                Map.of("FS05", "one.example.com/callback,four.example.com/callback")),
        FEATURE_FLAGS("featureFlags/testFeature", "false", Map.of("FS07", "true"));

        private final String path;
        private final String baseValue;
        private final Map<String, String> featureSetValues;

        TestConfiguration(String path, String baseValue, Map<String, String> featureSetValues) {
            this.path = path;
            this.baseValue = baseValue;
            this.featureSetValues = featureSetValues;
        }

        public void setupMockConfig(SSMProvider ssmProvider) {
            Mockito.lenient().when(ssmProvider.get("/test/core/" + path)).thenReturn(baseValue);
            final Path parameterPath = Path.of(path);
            final String terminal = parameterPath.getFileName().toString();
            final String basePath = parameterPath.getParent().toString();
            featureSetValues.forEach(
                    (featureSet, valueOverride) ->
                            Mockito.lenient()
                                    .when(
                                            ssmProvider.getMultiple(
                                                    "/test/core/features/"
                                                            + featureSet
                                                            + "/"
                                                            + basePath))
                                    .thenReturn(Map.of(terminal, valueOverride)));
        }

        public String getExpectedValue(String featureSet) {
            if (featureSet == null) {
                return baseValue;
            } else {
                return featureSetValues.getOrDefault(featureSet, baseValue);
            }
        }
    }

    @ParameterizedTest
    @CsvSource({
        "CREDENTIAL_ISSUERS,",
        "CREDENTIAL_ISSUERS,FS01",
    })
    void shouldAccountForFeatureSetWhenRetrievingParameters(String testSet, String featureSet) {
        configService = new ConfigService(ssmProvider, secretsProvider, featureSet);
        environmentVariables.set("ENVIRONMENT", "test");
        TestMultipleConfiguration testMultipleConfiguration =
                TestMultipleConfiguration.valueOf(testSet);
        testMultipleConfiguration.setupMockConfig(ssmProvider);
        assertEquals(
                testMultipleConfiguration.getExpectedValue(featureSet),
                configService.getSsmParameters(testMultipleConfiguration.path, false));
    }

    private enum TestFeatureFlag implements FeatureFlag {
        TEST_FEATURE("testFeature");
        private final String name;

        TestFeatureFlag(String name) {
            this.name = name;
        }

        @Override
        public String getName() {
            return this.name;
        }
    }

    private enum TestMultipleConfiguration {
        CREDENTIAL_ISSUERS(
                "credentialIssuers",
                Map.of(
                        "cri1/activeConnection",
                        "stub",
                        "cri1/connections/stub/clientId",
                        "ipv-core",
                        "cri2/activeConnection",
                        "main",
                        "cri2/connections/main/clientId",
                        "a client id"),
                Map.of(
                        "FS01",
                        Map.of("cri2/activeConnection", "stub", "cri3/activeConnection", "main")));

        private final String path;
        private final Map<String, String> baseValues;
        private final Map<String, Map<String, String>> featureSetValues;

        TestMultipleConfiguration(
                String path,
                Map<String, String> baseValues,
                Map<String, Map<String, String>> featureSetValues) {
            this.path = path;
            this.baseValues = baseValues;
            this.featureSetValues = featureSetValues;
        }

        public void setupMockConfig(SSMProvider ssmProvider) {
            Mockito.lenient()
                    .when(ssmProvider.getMultiple("/test/core/" + path))
                    .thenReturn(baseValues);
            featureSetValues.forEach(
                    (featureSet, valueOverride) ->
                            Mockito.lenient()
                                    .when(
                                            ssmProvider.getMultiple(
                                                    "/test/core/features/"
                                                            + featureSet
                                                            + "/"
                                                            + path))
                                    .thenReturn(valueOverride));
        }

        public Map<String, String> getExpectedValue(String featureSet) {
            if (featureSet == null) {
                return baseValues;
            } else {
                var expected = new HashMap<>(baseValues);
                expected.putAll(featureSetValues.get(featureSet));
                return expected;
            }
        }
    }

    @Test
    void shouldFetchCiMitConfig() throws ConfigException {
        environmentVariables.set("ENVIRONMENT", "test");
        when(ssmProvider.get("/test/core/cimit/config"))
                .thenReturn(
                        "{\""
                                + "X01\":{"
                                + "\"sameSessionStep\":\"/journey/j1\","
                                + "\"separateSessionStep\":\"/journey/j2\","
                                + "\"mitigatingCredentialIssuers\":[\"cri1\"]"
                                + "}}");
        Map<String, ContraIndicatorMitigation> expectedCiMitConfig =
                Map.of(
                        "X01",
                        ContraIndicatorMitigation.builder()
                                .sameSessionStep("/journey/j1")
                                .separateSessionStep("/journey/j2")
                                .mitigatingCredentialIssuers(List.of("cri1"))
                                .build());
        assertEquals(expectedCiMitConfig, configService.getCiMitConfig());
    }

    @Test
    void shouldThrowErrorOnInvalidCiMitConfig() {
        environmentVariables.set("ENVIRONMENT", "test");
        when(ssmProvider.get("/test/core/cimit/config")).thenReturn("}");
        assertThrows(ConfigException.class, () -> configService.getCiMitConfig());
    }
}
