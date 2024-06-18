package uk.gov.di.ipv.core.library.helpers;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.JWTClaimsSet;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.exceptions.CredentialParseException;
import uk.gov.di.model.AddressCredential;
import uk.gov.di.model.IdentityAssertionCredential;
import uk.gov.di.model.IdentityCheck;
import uk.gov.di.model.IdentityCheckCredential;
import uk.gov.di.model.RiskAssessmentCredential;
import uk.gov.di.model.SecurityCheckCredential;

import java.io.IOException;
import java.net.URISyntaxException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.text.ParseException;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

@ExtendWith(MockitoExtension.class)
class VerifiableCredentialParserTest {
    private final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    @Test
    void shouldParseAddressCredential() throws Exception {
        var claimsSet = getTestClaimsSet("/AddressCredential.json");

        var vc = VerifiableCredentialParser.parseCredential(claimsSet);

        assertInstanceOf(AddressCredential.class, vc);

        var addressCredential = (AddressCredential) vc;
        assertEquals(
                "S5 6UN",
                addressCredential.getCredentialSubject().getAddress().get(0).getPostalCode());
    }

    @Test
    void shouldParseIdentityAssertionCredential() throws Exception {
        var claimsSet = getTestClaimsSet("/IdentityAssertionCredential.json");

        var vc = VerifiableCredentialParser.parseCredential(claimsSet);

        assertInstanceOf(IdentityAssertionCredential.class, vc);

        var identityAssertionCredential = (IdentityAssertionCredential) vc;
        assertEquals(
                "1970-01-01",
                identityAssertionCredential
                        .getCredentialSubject()
                        .getBirthDate()
                        .get(0)
                        .getValue());
    }

    @Test
    void shouldParseIdentityCheckCredential() throws Exception {
        var claimsSet = getTestClaimsSet("/IdentityCheckCredential.json");

        var vc = VerifiableCredentialParser.parseCredential(claimsSet);

        assertInstanceOf(IdentityCheckCredential.class, vc);

        var identityCheckCredential = (IdentityCheckCredential) vc;
        assertEquals(
                IdentityCheck.IdentityCheckType.IDENTITY_CHECK_,
                identityCheckCredential.getEvidence().get(0).getType());
        assertEquals(
                "122345678",
                identityCheckCredential
                        .getCredentialSubject()
                        .getPassport()
                        .get(0)
                        .getDocumentNumber());
    }

    @Test
    void shouldParseRiskAssessmentCredential() throws Exception {
        var claimsSet = getTestClaimsSet("/RiskAssessmentCredential.json");

        var vc = VerifiableCredentialParser.parseCredential(claimsSet);

        assertInstanceOf(RiskAssessmentCredential.class, vc);

        var evidence = ((RiskAssessmentCredential) vc).getEvidence().get(0);
        assertEquals("RiskAssessment", evidence.getType());
        assertNotNull(evidence.getTxn());
    }

    @Test
    void shouldParseSecurityCheckCredential() throws Exception {
        var claimsSet = getTestClaimsSet("/SecurityCheckCredential.json");

        var vc = VerifiableCredentialParser.parseCredential(claimsSet);

        assertInstanceOf(SecurityCheckCredential.class, vc);

        var evidence = ((SecurityCheckCredential) vc).getEvidence().get(0);
        assertEquals("SecurityCheck", evidence.getType());
        assertEquals("XX", evidence.getContraIndicator().get(0).getCode());
    }

    @Test
    void shouldAllowAdditionalProperties() throws Exception {
        var claimsSet = getTestClaimsSet("/AdditionalPropertyCredential.json");

        var vc = VerifiableCredentialParser.parseCredential(claimsSet);

        assertInstanceOf(AddressCredential.class, vc);
    }

    @Test
    void shouldThrowOnInvalidProperties() throws Exception {
        var claimsSet = getTestClaimsSet("/InvalidPropertyCredential.json");

        assertThrows(
                CredentialParseException.class,
                () -> VerifiableCredentialParser.parseCredential(claimsSet));
    }

    @Test
    void shouldThrowOnInvalidCredentialType() throws Exception {
        var claimsSet = getTestClaimsSet("/InvalidTypeCredential.json");

        assertThrows(
                CredentialParseException.class,
                () -> VerifiableCredentialParser.parseCredential(claimsSet));
    }

    @Test
    void shouldThrowOnMissingCredentialType() throws Exception {
        var claimsSet = getTestClaimsSet("/MissingTypeCredential.json");

        assertThrows(
                CredentialParseException.class,
                () -> VerifiableCredentialParser.parseCredential(claimsSet));
    }

    private JWTClaimsSet getTestClaimsSet(String resource)
            throws IOException, URISyntaxException, ParseException {
        var resourcePath =
                Path.of(VerifiableCredentialParserTest.class.getResource(resource).toURI());
        var resourceContent = Files.readString(resourcePath);
        return JWTClaimsSet.parse(
                Map.of("vc", OBJECT_MAPPER.readValue(resourceContent, Map.class)));
    }
}
