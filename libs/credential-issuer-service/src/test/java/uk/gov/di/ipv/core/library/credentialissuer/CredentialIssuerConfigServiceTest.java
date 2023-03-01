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
import java.util.Objects;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@ExtendWith(SystemStubsExtension.class)
class CredentialIssuerConfigServiceTest {
    @SystemStub EnvironmentVariables environmentVariables;
    @Mock SSMProvider ssmProvider;
    @Mock SSMProvider ssmProvider2;
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

        environmentVariables.set(
                "CREDENTIAL_ISSUERS_CONFIG_PARAM_PREFIX", "/dev/core/credentialIssuers/");
        HashMap<String, String> response = new HashMap<>();
        response.put("passportCri/tokenUrl", "passportTokenUrl");
        response.put("passportCri/authorizeUrl", "passportAuthUrl");
        response.put("passportCri/id", "passportCri");
        response.put("passportCri/name", "passportIssuer");
        response.put("stubCri/tokenUrl", "stubTokenUrl");
        response.put("stubCri/authorizeUrl", "stubAuthUrl");
        response.put("stubCri/id", "stubCri");
        response.put("stubCri/name", "stubIssuer");

        when(ssmProvider.recursive()).thenReturn(ssmProvider2);
        when(ssmProvider2.getMultiple("/dev/core/credentialIssuers/")).thenReturn(response);
        List<CredentialIssuerConfig> result = credentialIssuerConfigService.getCredentialIssuers();

        assertEquals(2, result.size());

        Optional<CredentialIssuerConfig> passportIssuerConfig =
                result.stream()
                        .filter(config -> Objects.equals(config.getId(), "passportCri"))
                        .findFirst();
        assertTrue(passportIssuerConfig.isPresent());
        assertEquals("passportTokenUrl", passportIssuerConfig.get().getTokenUrl().toString());
        assertEquals("passportAuthUrl", passportIssuerConfig.get().getAuthorizeUrl().toString());
        assertEquals("passportCri", passportIssuerConfig.get().getId());

        Optional<CredentialIssuerConfig> stubIssuerConfig =
                result.stream()
                        .filter(config -> Objects.equals(config.getId(), "stubCri"))
                        .findFirst();
        assertTrue(stubIssuerConfig.isPresent());
        assertEquals("stubTokenUrl", stubIssuerConfig.get().getTokenUrl().toString());
        assertEquals("stubAuthUrl", stubIssuerConfig.get().getAuthorizeUrl().toString());
        assertEquals("stubCri", stubIssuerConfig.get().getId());
    }

    @Test
    void shouldThrowExceptionWhenCriConfigIsIncorrect() {
        environmentVariables.set(
                "CREDENTIAL_ISSUERS_CONFIG_PARAM_PREFIX", "/dev/core/credentialIssuers/");
        HashMap<String, String> response = new HashMap<>();
        response.put("incorrectPathName", "passportTokenUrl");
        response.put("passportCri/authorizeUrl", "passportAuthUrl");
        response.put("passportCri/id", "passportCri");
        response.put("passportCri/name", "passportIssuer");

        when(ssmProvider.recursive()).thenReturn(ssmProvider2);
        when(ssmProvider2.getMultiple("/dev/core/credentialIssuers/")).thenReturn(response);
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

        environmentVariables.set(
                "CREDENTIAL_ISSUERS_CONFIG_PARAM_PREFIX", "/dev/core/credentialIssuers/");
        HashMap<String, String> response = new HashMap<>();
        response.put("passportCri/id", "passportCri");
        response.put("passportCri/tokenUrl", "passportTokenUrl");
        response.put("stubCri/id", "stubCri");
        response.put("stubCri/tokenUrl", "stubTokenUrl");
        // This will be ignored - not in pojo
        response.put("stubCri/ipclientid", "stubIpClient");

        when(ssmProvider.recursive()).thenReturn(ssmProvider2);
        when(ssmProvider2.getMultiple("/dev/core/credentialIssuers/")).thenReturn(response);
        List<CredentialIssuerConfig> result = credentialIssuerConfigService.getCredentialIssuers();

        Optional<CredentialIssuerConfig> passportIssuerConfig =
                result.stream()
                        .filter(config -> Objects.equals(config.getId(), "passportCri"))
                        .findFirst();
        assertTrue(passportIssuerConfig.isPresent());
        assertEquals("passportTokenUrl", passportIssuerConfig.get().getTokenUrl().toString());

        Optional<CredentialIssuerConfig> stubIssuerConfig =
                result.stream()
                        .filter(config -> Objects.equals(config.getId(), "stubCri"))
                        .findFirst();
        assertTrue(stubIssuerConfig.isPresent());
        assertEquals("stubTokenUrl", stubIssuerConfig.get().getTokenUrl().toString());
    }
}
