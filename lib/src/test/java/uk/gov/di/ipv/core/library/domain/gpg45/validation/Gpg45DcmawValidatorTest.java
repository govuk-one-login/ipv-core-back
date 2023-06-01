package uk.gov.di.ipv.core.library.domain.gpg45.validation;

import org.junit.jupiter.api.Test;
import uk.gov.di.ipv.core.library.domain.gpg45.domain.CheckDetail;
import uk.gov.di.ipv.core.library.domain.gpg45.domain.CredentialEvidenceItem;

import java.util.Collections;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class Gpg45DcmawValidatorTest {

    @Test
    void isSuccessfulShouldReturnTrueOnValidCredential() {
        CredentialEvidenceItem credentialEvidenceItem =
                new CredentialEvidenceItem(
                        3,
                        2,
                        1,
                        2,
                        Collections.singletonList(new CheckDetail()),
                        null,
                        Collections.emptyList());

        assertTrue(Gpg45DcmawValidator.isSuccessful(credentialEvidenceItem));
    }

    @Test
    void isSuccessfulShouldReturnFalseOnInValidCredentialWithFailedCheckDetails() {
        CredentialEvidenceItem credentialEvidenceItem =
                new CredentialEvidenceItem(
                        3,
                        0,
                        1,
                        2,
                        null,
                        Collections.singletonList(new CheckDetail()),
                        Collections.emptyList());

        assertFalse(Gpg45DcmawValidator.isSuccessful(credentialEvidenceItem));
    }

    @Test
    void isSuccessfulShouldReturnFalseOnInValidCredentialWithIncorrectValidityScoreValue() {
        CredentialEvidenceItem credentialEvidenceItem =
                new CredentialEvidenceItem(
                        3,
                        0,
                        1,
                        2,
                        Collections.singletonList(new CheckDetail()),
                        null,
                        Collections.emptyList());

        assertFalse(Gpg45DcmawValidator.isSuccessful(credentialEvidenceItem));
    }
}
