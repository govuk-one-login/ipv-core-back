package uk.gov.di.ipv.core.library.domain.gpg45.validation;

import org.junit.jupiter.api.Test;
import uk.gov.di.ipv.core.library.domain.gpg45.Gpg45Profile;
import uk.gov.di.ipv.core.library.domain.gpg45.domain.CredentialEvidenceItem;

import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class Gpg45EvidenceValidatorTest {

    @Test
    void validateShouldReturnTrueIfM1AScoresAreMetWithEmptyCi() {
        CredentialEvidenceItem credentialEvidenceItem =
                new CredentialEvidenceItem(4, 2, Collections.emptyList());

        assertTrue(Gpg45EvidenceValidator.validate(credentialEvidenceItem, Gpg45Profile.M1A));
    }

    @Test
    void validateShouldReturnTrueIfM1AScoresAreMetWithNullCi() {
        CredentialEvidenceItem credentialEvidenceItem = new CredentialEvidenceItem(4, 2, null);

        assertTrue(Gpg45EvidenceValidator.validate(credentialEvidenceItem, Gpg45Profile.M1A));
    }

    @Test
    void validateShouldReturnFalseIfM1AStrengthValueIsNotMet() {
        CredentialEvidenceItem credentialEvidenceItem =
                new CredentialEvidenceItem(1, 2, Collections.emptyList());

        assertFalse(Gpg45EvidenceValidator.validate(credentialEvidenceItem, Gpg45Profile.M1A));
    }

    @Test
    void validateShouldReturnFalseIfM1AValidityValueIsNotMet() {
        CredentialEvidenceItem credentialEvidenceItem =
                new CredentialEvidenceItem(4, 0, Collections.emptyList());

        assertFalse(Gpg45EvidenceValidator.validate(credentialEvidenceItem, Gpg45Profile.M1A));
    }

    @Test
    void validateShouldReturnFalseIfM1AScoresAreMetButHasCI() {
        CredentialEvidenceItem credentialEvidenceItem =
                new CredentialEvidenceItem(4, 2, List.of("D02"));

        assertFalse(Gpg45EvidenceValidator.validate(credentialEvidenceItem, Gpg45Profile.M1A));
    }
}
