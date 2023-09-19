package uk.gov.di.ipv.core.library.gpg45.validators;

import org.junit.jupiter.api.Test;
import uk.gov.di.ipv.core.library.gpg45.domain.CheckDetail;
import uk.gov.di.ipv.core.library.gpg45.domain.CredentialEvidenceItem;

import java.util.Collections;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class Gpg45F2fValidatorTest {

    @Test
    void isSuccessfulShouldReturnTrueOnValidCredential() {
        CredentialEvidenceItem credentialEvidenceItem =
                new CredentialEvidenceItem(
                        4,
                        3,
                        0,
                        3,
                        Collections.singletonList(new CheckDetail()),
                        null,
                        Collections.emptyList());

        assertTrue(Gpg45F2fValidator.isSuccessful(credentialEvidenceItem));
    }

    @Test
    void isSuccessfulShouldReturnFalseOnInValidCredentialWithFailedCheckDetails() {
        CredentialEvidenceItem credentialEvidenceItem =
                new CredentialEvidenceItem(
                        4,
                        3,
                        0,
                        3,
                        null,
                        Collections.singletonList(new CheckDetail()),
                        Collections.emptyList());

        assertFalse(Gpg45F2fValidator.isSuccessful(credentialEvidenceItem));
    }

    @Test
    void isSuccessfulShouldReturnFalseOnInValidCredentialWithIncorrectValidityScoreValue() {
        CredentialEvidenceItem credentialEvidenceItem =
                new CredentialEvidenceItem(
                        3,
                        0,
                        0,
                        3,
                        Collections.singletonList(new CheckDetail()),
                        null,
                        Collections.emptyList());

        assertFalse(Gpg45F2fValidator.isSuccessful(credentialEvidenceItem));
    }
}
