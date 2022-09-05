package uk.gov.di.ipv.core.library.domain.gpg45.validation;

import org.junit.jupiter.api.Test;
import uk.gov.di.ipv.core.library.domain.gpg45.Gpg45Profile;
import uk.gov.di.ipv.core.library.domain.gpg45.domain.CredentialEvidenceItem;

import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DcmawEvidenceValidatorTest {
    @Test
    void validateShouldReturnTrueIfM1BScoresAreMetWithEmptyCi() {
        CredentialEvidenceItem credentialEvidenceItem =
                new CredentialEvidenceItem(3, 2, Collections.emptyList());

        assertTrue(DcmawEvidenceValidator.validate(credentialEvidenceItem, Gpg45Profile.M1B));
    }

    @Test
    void validateShouldReturnTrueIfM1BScoresAreMetWithNullCi() {
        CredentialEvidenceItem credentialEvidenceItem = new CredentialEvidenceItem(3, 2, null);

        assertTrue(DcmawEvidenceValidator.validate(credentialEvidenceItem, Gpg45Profile.M1B));
    }

    @Test
    void validateShouldReturnFalseIfM1BStrengthValueIsNotMet() {
        CredentialEvidenceItem credentialEvidenceItem =
                new CredentialEvidenceItem(1, 2, Collections.emptyList());

        assertFalse(DcmawEvidenceValidator.validate(credentialEvidenceItem, Gpg45Profile.M1B));
    }

    @Test
    void validateShouldReturnFalseIfM1BValidityValueIsNotMet() {
        CredentialEvidenceItem credentialEvidenceItem =
                new CredentialEvidenceItem(4, 0, Collections.emptyList());

        assertFalse(DcmawEvidenceValidator.validate(credentialEvidenceItem, Gpg45Profile.M1B));
    }

    @Test
    void validateShouldReturnFalseIfM1BScoresAreMetButHasCI() {
        CredentialEvidenceItem credentialEvidenceItem =
                new CredentialEvidenceItem(4, 2, List.of("D02"));

        assertFalse(DcmawEvidenceValidator.validate(credentialEvidenceItem, Gpg45Profile.M1B));
    }
}
