package uk.gov.di.ipv.core.library.gpg45.validators;

import org.junit.jupiter.api.Test;
import uk.gov.di.ipv.core.library.gpg45.domain.CredentialEvidenceItem;

import java.util.Collections;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class Gpg45FraudValidatorTest {
    @Test
    void isSuccessfulShouldReturnTrueOnValidCredential() {
        CredentialEvidenceItem credentialEvidenceItem =
                new CredentialEvidenceItem(
                        CredentialEvidenceItem.EvidenceType.IDENTITY_FRAUD,
                        2,
                        Collections.emptyList());

        assertTrue(Gpg45FraudValidator.isSuccessful(credentialEvidenceItem));
    }

    @Test
    void isSuccessfulShouldReturnFalseOnValidCredential() {
        CredentialEvidenceItem credentialEvidenceItem =
                new CredentialEvidenceItem(
                        CredentialEvidenceItem.EvidenceType.IDENTITY_FRAUD,
                        0,
                        Collections.emptyList());

        assertFalse(Gpg45FraudValidator.isSuccessful(credentialEvidenceItem));
    }
}
