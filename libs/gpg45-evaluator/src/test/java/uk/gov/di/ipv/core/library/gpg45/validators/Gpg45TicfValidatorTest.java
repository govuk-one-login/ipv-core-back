package uk.gov.di.ipv.core.library.gpg45.validators;

import org.junit.jupiter.api.Test;
import uk.gov.di.ipv.core.library.gpg45.domain.CredentialEvidenceItem;

import static org.junit.jupiter.api.Assertions.*;
import static uk.gov.di.ipv.core.library.gpg45.domain.CredentialEvidenceItem.TICF_EVIDENCE_TYPE;

class Gpg45TicfValidatorTest {

    @Test
    void isSuccessfulShouldReturnTrueOnValidCredential() {
        CredentialEvidenceItem credentialEvidenceItem =
                CredentialEvidenceItem.builder().type(TICF_EVIDENCE_TYPE).build();

        assertTrue(Gpg45TicfValidator.isSuccessful(credentialEvidenceItem));
    }

    @Test
    void isSuccessfulShouldReturnFalseOnValidCredential() {
        CredentialEvidenceItem credentialEvidenceItem =
                CredentialEvidenceItem.builder().type("IdentityCheck").build();

        assertFalse(Gpg45TicfValidator.isSuccessful(credentialEvidenceItem));
    }
}
