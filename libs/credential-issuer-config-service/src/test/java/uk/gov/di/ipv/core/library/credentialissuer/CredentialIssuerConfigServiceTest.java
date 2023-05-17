package uk.gov.di.ipv.core.library.credentialissuer;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import software.amazon.lambda.powertools.parameters.SSMProvider;
import software.amazon.lambda.powertools.parameters.SecretsProvider;
import uk.gov.di.ipv.core.library.dto.CredentialIssuerConfig;
import uk.gov.di.ipv.core.library.exceptions.ParseCredentialIssuerConfigException;
import uk.org.webcompere.systemstubs.environment.EnvironmentVariables;
import uk.org.webcompere.systemstubs.jupiter.SystemStub;
import uk.org.webcompere.systemstubs.jupiter.SystemStubsExtension;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@ExtendWith(SystemStubsExtension.class)
class CredentialIssuerConfigServiceTest {

    private static Map<String, String> TEST_CREDENTIAL_ISSUERS =
            Map.of(
                    "passportCri/tokenUrl",
                    "passportTokenUrl",
                    "passportCri/authorizeUrl",
                    "passportAuthUrl",
                    "passportCri/clientId",
                    "passportCri",
                    "passportCri/name",
                    "passportIssuer",
                    "stubCri/tokenUrl",
                    "stubTokenUrl",
                    "stubCri/authorizeUrl",
                    "stubAuthUrl",
                    "stubCri/clientId",
                    "stubCri",
                    "stubCri/name",
                    "stubIssuer",
                    "stubCri/allowedSharedAttributes",
                    "name, birthDate, address");
    @SystemStub EnvironmentVariables environmentVariables;
    @Mock SSMProvider ssmProvider;
    @Mock SecretsProvider secretsProvider;

    private CredentialIssuerConfigService credentialIssuerConfigService;

    @BeforeEach
    void setUp() {
        credentialIssuerConfigService =
                new CredentialIssuerConfigService(ssmProvider, secretsProvider);
    }

    @Test
    void shouldGetAllCredentialIssuersFromParameterStore()
            throws ParseCredentialIssuerConfigException {
        environmentVariables.set("ENVIRONMENT", "test");

        when(ssmProvider.recursive()).thenReturn(ssmProvider);
        when(ssmProvider.getMultiple("/test/core/credentialIssuers"))
                .thenReturn(TEST_CREDENTIAL_ISSUERS);

        List<CredentialIssuerConfig> result = credentialIssuerConfigService.getCredentialIssuers();

        assertEquals(2, result.size());

        Optional<CredentialIssuerConfig> passportIssuerConfig =
                result.stream()
                        .filter(config -> Objects.equals(config.getClientId(), "passportCri"))
                        .findFirst();
        assertTrue(passportIssuerConfig.isPresent());
        assertEquals("passportTokenUrl", passportIssuerConfig.get().getTokenUrl().toString());
        assertEquals("passportAuthUrl", passportIssuerConfig.get().getAuthorizeUrl().toString());
        assertEquals("passportCri", passportIssuerConfig.get().getClientId());

        Optional<CredentialIssuerConfig> stubIssuerConfig =
                result.stream()
                        .filter(config -> Objects.equals(config.getClientId(), "stubCri"))
                        .findFirst();
        assertTrue(stubIssuerConfig.isPresent());
        assertEquals("stubTokenUrl", stubIssuerConfig.get().getTokenUrl().toString());
        assertEquals("stubAuthUrl", stubIssuerConfig.get().getAuthorizeUrl().toString());
        assertEquals("stubCri", stubIssuerConfig.get().getClientId());
    }

    @Test
    void shouldThrowExceptionWhenCriConfigIsIncorrect() {
        environmentVariables.set("ENVIRONMENT", "test");
        Map<String, String> testResponse = new HashMap<>(TEST_CREDENTIAL_ISSUERS);
        testResponse.put("incorrectPathName", "passportTokenUrl");

        when(ssmProvider.recursive()).thenReturn(ssmProvider);
        when(ssmProvider.getMultiple("/test/core/credentialIssuers")).thenReturn(testResponse);
        ParseCredentialIssuerConfigException exception =
                assertThrows(
                        ParseCredentialIssuerConfigException.class,
                        () -> credentialIssuerConfigService.getCredentialIssuers());
        assertEquals(
                "The credential issuer id cannot be parsed from the parameter path incorrectPathName",
                exception.getMessage());
    }

    @Test
    void shouldGetAllCredentialIssuersFromParameterStoreNewAndIgnoreInExistingFields()
            throws ParseCredentialIssuerConfigException {
        environmentVariables.set("ENVIRONMENT", "test");
        Map<String, String> testResponse = new HashMap<>(TEST_CREDENTIAL_ISSUERS);
        // This will be ignored - not in pojo
        testResponse.put("stubCri/ipclientid", "stubIpClient");

        when(ssmProvider.recursive()).thenReturn(ssmProvider);
        when(ssmProvider.getMultiple("/test/core/credentialIssuers")).thenReturn(testResponse);
        List<CredentialIssuerConfig> result = credentialIssuerConfigService.getCredentialIssuers();

        Optional<CredentialIssuerConfig> passportIssuerConfig =
                result.stream()
                        .filter(config -> Objects.equals(config.getClientId(), "passportCri"))
                        .findFirst();
        assertTrue(passportIssuerConfig.isPresent());
        assertEquals("passportTokenUrl", passportIssuerConfig.get().getTokenUrl().toString());

        Optional<CredentialIssuerConfig> stubIssuerConfig =
                result.stream()
                        .filter(config -> Objects.equals(config.getClientId(), "stubCri"))
                        .findFirst();
        assertTrue(stubIssuerConfig.isPresent());
        assertEquals("stubTokenUrl", stubIssuerConfig.get().getTokenUrl().toString());
    }

    @Test
    void shouldGetAllCredentialIssuersFromParameterStoreWithFeatureSetOverrides()
            throws ParseCredentialIssuerConfigException {
        environmentVariables.set("ENVIRONMENT", "test");
        Map<String, String> featureSetResponse =
                Map.of(
                        "passportCri/tokenUrl", "passportTokenUrlForFS01",
                        "featureSetCri/tokenUrl", "featureSetTokenUrl",
                        "featureSetCri/clientId", "featureSetCri");

        when(ssmProvider.recursive()).thenReturn(ssmProvider);
        when(ssmProvider.getMultiple("/test/core/credentialIssuers"))
                .thenReturn(TEST_CREDENTIAL_ISSUERS);
        when(ssmProvider.getMultiple("/test/core/features/FS01/credentialIssuers"))
                .thenReturn(featureSetResponse);

        credentialIssuerConfigService.setFeatureSet("FS01");
        List<CredentialIssuerConfig> result = credentialIssuerConfigService.getCredentialIssuers();

        assertEquals(3, result.size());

        Optional<CredentialIssuerConfig> passportIssuerConfig =
                result.stream()
                        .filter(config -> Objects.equals(config.getClientId(), "passportCri"))
                        .findFirst();
        assertTrue(passportIssuerConfig.isPresent());
        assertEquals(
                "passportTokenUrlForFS01", passportIssuerConfig.get().getTokenUrl().toString());
        assertEquals("passportAuthUrl", passportIssuerConfig.get().getAuthorizeUrl().toString());
        assertEquals("passportCri", passportIssuerConfig.get().getClientId());

        Optional<CredentialIssuerConfig> stubIssuerConfig =
                result.stream()
                        .filter(config -> Objects.equals(config.getClientId(), "stubCri"))
                        .findFirst();
        assertTrue(stubIssuerConfig.isPresent());
        assertEquals("stubTokenUrl", stubIssuerConfig.get().getTokenUrl().toString());
        assertEquals("stubAuthUrl", stubIssuerConfig.get().getAuthorizeUrl().toString());
        assertEquals("stubCri", stubIssuerConfig.get().getClientId());

        Optional<CredentialIssuerConfig> featureSetIssuerConfig =
                result.stream()
                        .filter(config -> Objects.equals(config.getClientId(), "featureSetCri"))
                        .findFirst();
        assertTrue(featureSetIssuerConfig.isPresent());
        assertEquals("featureSetTokenUrl", featureSetIssuerConfig.get().getTokenUrl().toString());
        assertEquals("featureSetCri", featureSetIssuerConfig.get().getClientId());
    }
}
