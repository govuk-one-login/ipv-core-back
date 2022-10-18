package uk.gov.di.ipv.core.library.domain.gpg45.validation;

import org.junit.jupiter.api.Test;
import uk.gov.di.ipv.core.library.domain.gpg45.domain.CredentialEvidenceItem;

import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class Gpg45EvidenceValidatorTest {
    @Test
    void isSuccessfulShouldReturnTrueOnValidCredential() {
        CredentialEvidenceItem credentialEvidenceItem =
                new CredentialEvidenceItem(4, 2, Collections.emptyList());

        assertTrue(Gpg45EvidenceValidator.isSuccessful(credentialEvidenceItem));
    }

    @Test
    void isSuccessfulShouldReturnFalseOnValidCredential() {
        CredentialEvidenceItem credentialEvidenceItem =
                new CredentialEvidenceItem(4, 0, Collections.emptyList());

        assertFalse(Gpg45EvidenceValidator.isSuccessful(credentialEvidenceItem));
    }

    @Test
    void isSuccessfulShouldReturnFalseIfCredentialContainsCi() {
        CredentialEvidenceItem credentialEvidenceItem =
                new CredentialEvidenceItem(4, 2, List.of("D02"));

        assertFalse(Gpg45EvidenceValidator.isSuccessful(credentialEvidenceItem));
    }
}
