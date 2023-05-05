package uk.gov.di.ipv.core.library.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.tomakehurst.wiremock.junit5.WireMockRuntimeInfo;
import com.github.tomakehurst.wiremock.junit5.WireMockTest;
import com.google.gson.Gson;
import org.junit.jupiter.api.BeforeEach;
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
import software.amazon.awssdk.services.ssm.model.ParameterNotFoundException;
import software.amazon.lambda.powertools.parameters.SSMProvider;
import software.amazon.lambda.powertools.parameters.SecretsProvider;
import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
import uk.gov.di.ipv.core.library.domain.ContraIndicatorScore;
import uk.gov.di.ipv.core.library.dto.CredentialIssuerConfig;
import uk.org.webcompere.systemstubs.environment.EnvironmentVariables;
import uk.org.webcompere.systemstubs.jupiter.SystemStub;
import uk.org.webcompere.systemstubs.jupiter.SystemStubsExtension;
import uk.org.webcompere.systemstubs.properties.SystemProperties;

import java.net.URI;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static com.github.tomakehurst.wiremock.client.WireMock.getAllServeEvents;
import static com.github.tomakehurst.wiremock.client.WireMock.ok;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.stubFor;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.RSA_ENCRYPTION_PUBLIC_JWK;

@WireMockTest(httpPort = ConfigService.LOCALHOST_PORT)
@ExtendWith(MockitoExtension.class)
@ExtendWith(SystemStubsExtension.class)
class ConfigServiceTest {

    private static final String TEST_TOKEN_URL = "testTokenUrl";
    private static final String TEST_CREDENTIAL_URL = "testCredentialUrl";
    private static final String TEST_REDIRECT_URL = "http:example.com/callbackUrl/testCri";
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

    @Test
    void shouldGetCredentialIssuerFromParameterStore() throws Exception {
        environmentVariables.set("ENVIRONMENT", "test");
        Map<String, String> credentialIssuerParameters =
                Map.of(
                        "activeConnection",
                        "stub",
                        "tokenUrl",
                        TEST_TOKEN_URL,
                        "credentialUrl",
                        TEST_CREDENTIAL_URL,
                        "encryptionKey",
                        RSA_ENCRYPTION_PUBLIC_JWK,
                        "requiresApiKey",
                        "true");
        when(ssmProvider.get("/test/core/credentialIssuers/passportCri/activeConnection"))
                .thenReturn("stub");

        when(ssmProvider.getMultiple("/test/core/credentialIssuers/passportCri/connections/stub"))
                .thenReturn(credentialIssuerParameters);

        CredentialIssuerConfig result =
                configService.getCredentialIssuerActiveConnectionConfig("passportCri");

        CredentialIssuerConfig expected =
                new CredentialIssuerConfig(
                        URI.create(TEST_TOKEN_URL),
                        URI.create(TEST_CREDENTIAL_URL),
                        URI.create(TEST_CREDENTIAL_URL),
                        "ipv-core",
                        "{}",
                        RSA_ENCRYPTION_PUBLIC_JWK,
                        "test-audience",
                        URI.create(TEST_REDIRECT_URL),
                        true);

        assertEquals(expected.getTokenUrl(), result.getTokenUrl());
        assertEquals(expected.getCredentialUrl(), result.getCredentialUrl());
        assertEquals("RSA", result.getEncryptionKey().getKeyType().toString());
        assertTrue(result.getRequiresApiKey());
    }

    @Test
    void shouldReturnIsEnabled() {
        environmentVariables.set("ENVIRONMENT", "test");
        when(ssmProvider.get("/test/core/credentialIssuers/passportCri/enabled"))
                .thenReturn("true");

        boolean isEnabled = configService.isEnabled("passportCri");
        assertTrue(isEnabled);
    }

    @Test
    void shouldReturnIsAvailableOrNot() {
        environmentVariables.set("ENVIRONMENT", "test");
        when(ssmProvider.get("/test/core/credentialIssuers/passportCri/unavailable"))
                .thenReturn("false");

        boolean isUnavailable = configService.isUnavailable("passportCri");
        assertFalse(isUnavailable);
    }

    @Test
    void shouldReturnAllowedSharedAttributes() {
        environmentVariables.set("ENVIRONMENT", "test");
        when(ssmProvider.get("/test/core/credentialIssuers/passportCri/allowedSharedAttributes"))
                .thenReturn("address,name");

        String sharedAttributes = configService.getAllowedSharedAttributes("passportCri");
        assertEquals("address,name", sharedAttributes);
    }

    @Test
    void shouldReturnListOfClientRedirectUrls() {
        environmentVariables.set("ENVIRONMENT", "test");
        when(ssmProvider.get("/test/core/clients/aClientId/validRedirectUrls"))
                .thenReturn(
                        "one.example.com/callback,two.example.com/callback,three.example.com/callback");

        var fetchedClientRedirectUrls = configService.getClientRedirectUrls("aClientId");

        var expectedRedirectUrls =
                List.of(
                        "one.example.com/callback",
                        "two.example.com/callback",
                        "three.example.com/callback");
        assertEquals(expectedRedirectUrls, fetchedClientRedirectUrls);
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
    void shouldGetContraIndicatorScoresMap() {
        String scoresJsonString =
                "[{ \"ci\": \"X01\", \"detectedScore\": 3, \"checkedScore\": -3, \"fidCode\": \"YZ01\" }, { \"ci\": \"Z03\", \"detectedScore\": 5, \"checkedScore\": -3 }]";
        when(secretsProvider.get(any())).thenReturn(scoresJsonString);

        Map<String, ContraIndicatorScore> scoresMap = configService.getContraIndicatorScoresMap();

        assertEquals(2, scoresMap.size());
        assertTrue(scoresMap.containsKey("X01"));
        assertTrue(scoresMap.containsKey("Z03"));
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
                Map.of("FS01", TEST_CERT_FS01),
                Map.of()),
        CLIENT_ISSUER(
                "clients/aClientId/issuer",
                "aClientIssuer",
                Map.of("FS02", "aDifferentIssuer"),
                Map.of("FS03_NO_OVERRIDE", ParameterNotFoundException.class)),
        MAX_ALLOWED_AUTH_CLIENT_TTL(
                "self/maxAllowedAuthClientTtl",
                "aClientTokenTtl",
                Map.of("FS01", "aDifferentClientTokenTtl"),
                Map.of()),
        CORE_FRONT_CALLBACK_URL(
                "self/coreFrontCallbackUrl",
                "aCoreFrontCallbackUrl",
                Map.of("FS01", "aDifferentCoreFrontCallbackUrl"),
                Map.of()),
        CORE_VTM_CLAIM(
                "self/coreVtmClaim",
                "aCoreVtmClaim",
                Map.of("FS02", "aDifferentCoreVtmClaim"),
                Map.of()),
        BACKEND_SESSION_TIMEOUT(
                "self/backendSessionTimeout",
                "7200",
                Map.of("FS02", "7300", "FS03", "7400"),
                Map.of()),
        BACKEND_SESSION_TTL(
                "self/backendSessionTtl",
                "3600",
                Map.of("FS03", "3700", "FS04", "3800"),
                Map.of("FS05_NO_OVERRIDE", ParameterNotFoundException.class));

        private final String path;
        private final String baseValue;
        private final Map<String, String> featureSetValues;
        private final Map<String, Class> featureSetExceptions;

        TestConfiguration(
                String path,
                String baseValue,
                Map<String, String> featureSetValues,
                Map<String, Class> featureSetExceptions) {
            this.path = path;
            this.baseValue = baseValue;
            this.featureSetValues = featureSetValues;
            this.featureSetExceptions = featureSetExceptions;
        }

        public void setupMockConfig(SSMProvider ssmProvider) {
            Mockito.lenient().when(ssmProvider.get("/test/core/" + path)).thenReturn(baseValue);
            featureSetValues.forEach(
                    (featureSet, valueOverride) ->
                            Mockito.lenient()
                                    .when(
                                            ssmProvider.get(
                                                    "/test/core/featureSet/"
                                                            + featureSet
                                                            + "/"
                                                            + path))
                                    .thenReturn(valueOverride));
            featureSetExceptions.forEach(
                    (featureSet, clazz) ->
                            Mockito.lenient()
                                    .when(
                                            ssmProvider.get(
                                                    "/test/core/featureSet/"
                                                            + featureSet
                                                            + "/"
                                                            + path))
                                    .thenThrow(clazz));
        }

        public String getExpectedValue(String featureSet) {
            if (featureSet == null) {
                return baseValue;
            } else {
                return featureSetValues.getOrDefault(featureSet, baseValue);
            }
        }
    }
}
