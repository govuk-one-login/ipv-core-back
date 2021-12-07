package uk.gov.di.ipv.helpers;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import uk.gov.di.ipv.dto.CredentialIssuerConfig;
import uk.gov.di.ipv.dto.CredentialIssuers;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class Base64YamlTransformerTest {
    public static final String CREDENTIAL_ISSUER_CONFIG_BASE64 = "Y3JlZGVudGlhbElzc3VlckNvbmZpZ3M6CiAgLSBpZDogUGFzc3BvcnRJc3N1ZXIKICAgIHRva2VuVXJsOiBodHRwOi8vd3d3LmV4YW1wbGUuY29tCiAgICBjcmVkZW50aWFsVXJsOiBodHRwOi8vd3d3LmV4YW1wbGUuY29tL2NyZWRlbnRpYWwKICAtIGlkOiBGcmF1ZElzc3VlcgogICAgdG9rZW5Vcmw6IGh0dHA6Ly93d3cuZXhhbXBsZS5jb20KICAgIGNyZWRlbnRpYWxVcmw6IGh0dHA6Ly93d3cuZXhhbXBsZS5jb20vY3JlZGVudGlhbA==";

    private static CredentialIssuers expectedCredentialIssuers;
    private static final Base64YamlTransformer<CredentialIssuers> transformer =  new Base64YamlTransformer();

    @BeforeAll
    static void setUp() throws URISyntaxException {
        expectedCredentialIssuers = new CredentialIssuers(
                Set.of(
                        new CredentialIssuerConfig(
                                "PassportIssuer",
                                new URI("http://www.example.com"),
                                new URI("http://www.example.com/credential")
                        ),
                        new CredentialIssuerConfig(
                                "FraudIssuer",
                                new URI("http://www.example.com"),
                                new URI("http://www.example.com/credential")
                        )
                )
        );
    }

    @Test
    void shouldLoadCredentialIssuersFromBase64EncodedString() {
        assertEquals(
                expectedCredentialIssuers,
                transformer.applyTransformation(CREDENTIAL_ISSUER_CONFIG_BASE64, CredentialIssuers.class)
        );
    }

    @Test
    void shouldThrowWhenUnableToDecodeString()  {
        IllegalArgumentException exception = assertThrows(IllegalArgumentException.class, () -> {
            transformer.applyTransformation("Definitely not Bas64", CredentialIssuers.class);
        });
        assertEquals(
                "Input is expected to be encoded in multiple of 4 bytes but found: 18",
                exception.getMessage()
        );
    }
}
