package uk.gov.di.ipv.helpers;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Set;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import uk.gov.di.ipv.domain.CredentialIssuerException;
import uk.gov.di.ipv.dto.CredentialIssuerConfig;
import uk.gov.di.ipv.dto.CredentialIssuers;

class CredentialIssuerLoaderTest {

    public static final String CREDENTIAL_ISSUER_CONFIG_BASE64 = "Y3JlZGVudGlhbElzc3VlckNvbmZpZ3M6CiAgLSBpZDogUGFzc3BvcnRJc3N1ZXIKICAgIHRva2VuVXJsOiBodHRwOi8vd3d3LmV4YW1wbGUuY29tCiAgICBjcmVkZW50aWFsVXJsOiBodHRwOi8vd3d3LmV4YW1wbGUuY29tL2NyZWRlbnRpYWwKICAtIGlkOiBGcmF1ZElzc3VlcgogICAgdG9rZW5Vcmw6IGh0dHA6Ly93d3cuZXhhbXBsZS5jb20KICAgIGNyZWRlbnRpYWxVcmw6IGh0dHA6Ly93d3cuZXhhbXBsZS5jb20vY3JlZGVudGlhbA==";

    private CredentialIssuers expectedCredentialIssuers;

    @BeforeEach
    void setUp() throws URISyntaxException {
        expectedCredentialIssuers = new CredentialIssuers(Set.of(new CredentialIssuerConfig("PassportIssuer", new URI("http://www.example.com"), new URI("http://www.example.com/credential")), new CredentialIssuerConfig("FraudIssuer", new URI("http://www.example.com"), new URI("http://www.example.com/credential"))));
    }

    @Test
    void shouldLoadCredentialIssuersFromBase64EncodedString() {
        assertEquals(expectedCredentialIssuers, CredentialIssuerLoader.loadCredentialIssuers(CREDENTIAL_ISSUER_CONFIG_BASE64));
    }

    @Test
    void shouldThrowCredentialIssuerExceptionWhenUnableToDecodeString()  {
        CredentialIssuerException thrownCredentialIssuerException = assertThrows(CredentialIssuerException.class, () -> CredentialIssuerLoader.loadCredentialIssuers("asd"));
        assertTrue(thrownCredentialIssuerException.getErrorResponse().getMessage().contains("Failed to decode credential issuers config to credential issuers object"));
    }
}