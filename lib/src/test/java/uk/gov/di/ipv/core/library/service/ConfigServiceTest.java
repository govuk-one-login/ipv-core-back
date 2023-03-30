package uk.gov.di.ipv.core.library.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.tomakehurst.wiremock.junit5.WireMockRuntimeInfo;
import com.github.tomakehurst.wiremock.junit5.WireMockTest;
import com.google.gson.Gson;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import software.amazon.awssdk.services.secretsmanager.model.DecryptionFailureException;
import software.amazon.awssdk.services.secretsmanager.model.InternalServiceErrorException;
import software.amazon.awssdk.services.secretsmanager.model.InvalidParameterException;
import software.amazon.awssdk.services.secretsmanager.model.InvalidRequestException;
import software.amazon.awssdk.services.secretsmanager.model.ResourceNotFoundException;
import software.amazon.lambda.powertools.parameters.SSMProvider;
import software.amazon.lambda.powertools.parameters.SecretsProvider;
import uk.gov.di.ipv.core.library.domain.ContraIndicatorScore;
import uk.gov.di.ipv.core.library.dto.CredentialIssuerConfig;
import uk.org.webcompere.systemstubs.environment.EnvironmentVariables;
import uk.org.webcompere.systemstubs.jupiter.SystemStub;
import uk.org.webcompere.systemstubs.jupiter.SystemStubsExtension;
import uk.org.webcompere.systemstubs.properties.SystemProperties;

import java.net.URI;
import java.security.cert.CertificateException;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static com.github.tomakehurst.wiremock.client.WireMock.getAllServeEvents;
import static com.github.tomakehurst.wiremock.client.WireMock.ok;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.stubFor;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.ADDRESS_CRI_ID;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.BACKEND_SESSION_TIMEOUT;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.BACKEND_SESSION_TTL;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.CLIENT_ISSUER;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.CORE_FRONT_CALLBACK_URL;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.CORE_VTM_CLAIM;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.FRAUD_CRI_ID;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.KBV_CRI_ID;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.MAX_ALLOWED_AUTH_CLIENT_TTL;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.PASSPORT_CRI_ID;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.PUBLIC_KEY_MATERIAL_FOR_CORE_TO_VERIFY;
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

    @SystemStub private EnvironmentVariables environmentVariables;

    @SystemStub private SystemProperties systemProperties;

    @Mock SSMProvider ssmProvider;

    @Mock SSMProvider ssmProvider2;

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
        environmentVariables.set(
                "CREDENTIAL_ISSUERS_CONFIG_PARAM_PREFIX", "/dev/core/credentialIssuers");

        Map<String, String> credentialIssuerParameters =
                Map.of(
                        "activeConnection",
                        "stub",
                        "tokenUrl",
                        TEST_TOKEN_URL,
                        "credentialUrl",
                        TEST_CREDENTIAL_URL,
                        "jarEncryptionPublicJwk",
                        RSA_ENCRYPTION_PUBLIC_JWK);
        when(ssmProvider.get("/dev/core/credentialIssuers/passportCri/activeConnection"))
                .thenReturn("stub");

        when(ssmProvider.getMultiple("/dev/core/credentialIssuers/passportCri/connections/stub"))
                .thenReturn(credentialIssuerParameters);

        CredentialIssuerConfig result =
                configService.getCredentialIssuerActiveConnectionConfig("passportCri");

        CredentialIssuerConfig expected =
                new CredentialIssuerConfig(
                        "passportCri",
                        "",
                        URI.create(TEST_TOKEN_URL),
                        URI.create(TEST_CREDENTIAL_URL),
                        URI.create(TEST_CREDENTIAL_URL),
                        "ipv-core",
                        "{}",
                        RSA_ENCRYPTION_PUBLIC_JWK,
                        "test-audience",
                        URI.create(TEST_REDIRECT_URL));

        assertEquals(expected.getTokenUrl(), result.getTokenUrl());
        assertEquals(expected.getCredentialUrl(), result.getCredentialUrl());
        assertEquals("RSA", result.getJarEncryptionPublicJwk().getKeyType().toString());
    }

    @Test
    void shouldReturnIsEnabled() {
        environmentVariables.set("CREDENTIAL_ISSUERS_CONFIG_PARAM_PREFIX", "passportCri");
        when(ssmProvider.get("passportCri/aClientId/enabled")).thenReturn("true");

        boolean isEnabled = configService.isEnabled("aClientId");
        assertTrue(isEnabled);
    }

    @Test
    void shouldReturnIsAvailableOrNot() {
        environmentVariables.set("CREDENTIAL_ISSUERS_CONFIG_PARAM_PREFIX", "passportCri");
        when(ssmProvider.get("passportCri/aClientId/unavailable")).thenReturn("false");

        boolean isUnavailable = configService.isUnavailable("aClientId");
        assertFalse(isUnavailable);
    }

    @Test
    void shouldReturnAllowedSharedAttributes() {
        environmentVariables.set("CREDENTIAL_ISSUERS_CONFIG_PARAM_PREFIX", "passportCri");
        when(ssmProvider.get("passportCri/aClientId/allowedSharedAttributes"))
                .thenReturn("address,name");

        String sharedAttributes = configService.getAllowedSharedAttributes("aClientId");
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
    void shouldReturnValidClientCertificateForAuth() throws CertificateException {
        environmentVariables.set("ENVIRONMENT", "test");
        when(ssmProvider.get("/test/core/clients/aClientId/publicKeyMaterialForCoreToVerify"))
                .thenReturn(TEST_CERT);

        assertEquals(
                TEST_CERT,
                configService.getSsmParameter(PUBLIC_KEY_MATERIAL_FOR_CORE_TO_VERIFY, "aClientId"));
    }

    @Test
    void shouldReturnClientIssuer() {
        environmentVariables.set("ENVIRONMENT", "test");
        String clientIssuer = "aClientIssuer";
        when(ssmProvider.get("/test/core/clients/aClientId/issuer")).thenReturn(clientIssuer);
        assertEquals(clientIssuer, configService.getSsmParameter(CLIENT_ISSUER, "aClientId"));
    }

    @Test
    void shouldReturnMaxAllowedAuthClientTtl() {
        environmentVariables.set("ENVIRONMENT", "test");
        String clientIssuer = "aClientTokenTtl";
        when(ssmProvider.get("/test/core/self/maxAllowedAuthClientTtl")).thenReturn(clientIssuer);
        assertEquals(clientIssuer, configService.getSsmParameter(MAX_ALLOWED_AUTH_CLIENT_TTL));
    }

    @Test
    void shouldReturnCoreFrontCallbackUrl() {
        environmentVariables.set("ENVIRONMENT", "test");
        String coreFrontCallbackUrl = "aCoreFrontCallbackUrl";
        when(ssmProvider.get("/test/core/self/coreFrontCallbackUrl"))
                .thenReturn(coreFrontCallbackUrl);
        assertEquals(coreFrontCallbackUrl, configService.getSsmParameter(CORE_FRONT_CALLBACK_URL));
    }

    @Test
    void shouldReturnCoreVtmClaim() {
        environmentVariables.set("ENVIRONMENT", "test");
        String coreVtmClaim = "aCoreVtmClaim";
        when(ssmProvider.get("/test/core/self/coreVtmClaim")).thenReturn(coreVtmClaim);
        assertEquals(coreVtmClaim, configService.getSsmParameter(CORE_VTM_CLAIM));
    }

    @Test
    void shouldReturnPassportCriId() {
        environmentVariables.set("ENVIRONMENT", "test");
        String passportCriId = "ukPassport";
        when(ssmProvider.get("/test/core/self/journey/passportCriId")).thenReturn(passportCriId);
        assertEquals(passportCriId, configService.getSsmParameter(PASSPORT_CRI_ID));
    }

    @Test
    void shouldReturnAddressCriId() {
        environmentVariables.set("ENVIRONMENT", "test");
        String addressCriId = "address";
        when(ssmProvider.get("/test/core/self/journey/addressCriId")).thenReturn(addressCriId);
        assertEquals(addressCriId, configService.getSsmParameter(ADDRESS_CRI_ID));
    }

    @Test
    void shouldReturnFraudCriId() {
        environmentVariables.set("ENVIRONMENT", "test");
        String fraudCriId = "fraud";
        when(ssmProvider.get("/test/core/self/journey/fraudCriId")).thenReturn(fraudCriId);
        assertEquals(fraudCriId, configService.getSsmParameter(FRAUD_CRI_ID));
    }

    @Test
    void shouldReturnKbvCriId() {
        environmentVariables.set("ENVIRONMENT", "test");
        String kbvCriId = "kbv";
        when(ssmProvider.get("/test/core/self/journey/kbvCriId")).thenReturn(kbvCriId);
        assertEquals(kbvCriId, configService.getSsmParameter(KBV_CRI_ID));
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
    void shouldReturnBackendSessionTimeout() {
        environmentVariables.set("ENVIRONMENT", "test");
        String ttl = "7200";
        when(ssmProvider.get("/test/core/self/backendSessionTimeout")).thenReturn(ttl);
        assertEquals(ttl, configService.getSsmParameter(BACKEND_SESSION_TIMEOUT));
    }

    @Test
    void shouldReturnBackendSessionTtl() {
        environmentVariables.set("ENVIRONMENT", "test");
        when(ssmProvider.get("/test/core/self/backendSessionTtl")).thenReturn("7200");
        assertEquals("7200", configService.getSsmParameter(BACKEND_SESSION_TTL));
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
}
