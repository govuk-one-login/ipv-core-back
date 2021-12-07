package uk.gov.di.ipv.service;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import software.amazon.lambda.powertools.parameters.SSMProvider;
import uk.gov.di.ipv.dto.CredentialIssuerConfig;
import uk.gov.di.ipv.dto.CredentialIssuers;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class ConfigurationServiceTest {

    public static final String CREDENTIAL_ISSUER_CONFIG_BASE64 =
            "Y3JlZGVudGlhbElzc3VlckNvbmZpZ3M6CiAgLSBpZDogUGFzc3BvcnRJc3N1ZXIKICAgIHRva2VuVXJsOiBodHRwOi8vd3d3LmV4YW1wbGUuY29tCiAgICBjcmVkZW50aWFsVXJsOiBodHRwOi8vd3d3LmV4YW1wbGUuY29tL2NyZWRlbnRpYWwKICAtIGlkOiBGcmF1ZElzc3VlcgogICAgdG9rZW5Vcmw6IGh0dHA6Ly93d3cuZXhhbXBsZS5jb20KICAgIGNyZWRlbnRpYWxVcmw6IGh0dHA6Ly93d3cuZXhhbXBsZS5jb20vY3JlZGVudGlhbA==";
    @Mock SSMProvider ssmProvider;

    @Test
    void getCredentialIssuers() throws URISyntaxException {
        CredentialIssuers credentialIssuers =
                new CredentialIssuers(
                        Set.of(
                                new CredentialIssuerConfig(
                                        "PassportIssuer",
                                        new URI("http://www.example.com"),
                                        new URI("http://www.example.com/credential")),
                                new CredentialIssuerConfig(
                                        "FraudIssuer",
                                        new URI("http://www.example.com"),
                                        new URI("http://www.example.com/credential"))));

        when(ssmProvider.get(any())).thenReturn(CREDENTIAL_ISSUER_CONFIG_BASE64);

        ConfigurationService underTest = new ConfigurationService(ssmProvider);
        assertEquals(credentialIssuers, underTest.getCredentialIssuers());
    }
}
