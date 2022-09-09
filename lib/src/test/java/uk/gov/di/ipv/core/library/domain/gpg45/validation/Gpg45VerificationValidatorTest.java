package uk.gov.di.ipv.core.library.domain.gpg45.validation;

import org.junit.jupiter.api.Test;
import uk.gov.di.ipv.core.library.domain.gpg45.Gpg45Profile;
import uk.gov.di.ipv.core.library.domain.gpg45.domain.CredentialEvidenceItem;

import java.util.Collections;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class Gpg45VerificationValidatorTest {
    @Test
    void validateShouldReturnTrueIfM1AScoresAreMetWithEmptyCi() {
        CredentialEvidenceItem credentialEvidenceItem =
                new CredentialEvidenceItem(
                        CredentialEvidenceItem.EvidenceType.VERIFICATION,
                        2,
                        Collections.emptyList());

        assertTrue(Gpg45VerificationValidator.validate(credentialEvidenceItem, Gpg45Profile.M1A));
    }

    @Test
    void validateShouldReturnTrueIfM1AScoresAreMetWithNullCi() {
        CredentialEvidenceItem credentialEvidenceItem =
                new CredentialEvidenceItem(
                        CredentialEvidenceItem.EvidenceType.VERIFICATION, 2, null);

        assertTrue(Gpg45VerificationValidator.validate(credentialEvidenceItem, Gpg45Profile.M1A));
    }

    @Test
    void validateShouldReturnFalseIfM1AVerificationValueIsNotMet() {
        CredentialEvidenceItem credentialEvidenceItem =
                new CredentialEvidenceItem(
                        CredentialEvidenceItem.EvidenceType.VERIFICATION,
                        0,
                        Collections.emptyList());

        assertFalse(Gpg45VerificationValidator.validate(credentialEvidenceItem, Gpg45Profile.M1A));
    }

    @Test
    void isSuccessfulShouldReturnTrueOnValidCredential() {
        CredentialEvidenceItem credentialEvidenceItem =
                new CredentialEvidenceItem(
                        CredentialEvidenceItem.EvidenceType.VERIFICATION,
                        2,
                        Collections.emptyList());

        assertTrue(Gpg45VerificationValidator.isSuccessful(credentialEvidenceItem));
    }

    @Test
    void isSuccessfulShouldReturnFalseOnValidCredential() {
        CredentialEvidenceItem credentialEvidenceItem =
                new CredentialEvidenceItem(
                        CredentialEvidenceItem.EvidenceType.VERIFICATION,
                        0,
                        Collections.emptyList());

        assertFalse(Gpg45VerificationValidator.isSuccessful(credentialEvidenceItem));
    }
}
