package uk.gov.di.ipv.core.library.domain.gpg45.validation;

import org.junit.jupiter.api.Test;
import uk.gov.di.ipv.core.library.domain.gpg45.Gpg45Profile;
import uk.gov.di.ipv.core.library.domain.gpg45.domain.CredentialEvidenceItem;

import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class Gpg45FraudValidatorTest {
    @Test
    void validateShouldReturnTrueIfM1AScoresAreMetWithEmptyCi() {
        CredentialEvidenceItem credentialEvidenceItem =
                new CredentialEvidenceItem(
                        CredentialEvidenceItem.EvidenceType.IDENTITY_FRAUD,
                        1,
                        Collections.emptyList());

        assertTrue(Gpg45FraudValidator.validate(credentialEvidenceItem, Gpg45Profile.M1A));
    }

    @Test
    void validateShouldReturnTrueIfM1BScoresAreMetWithEmptyCi() {
        CredentialEvidenceItem credentialEvidenceItem =
                new CredentialEvidenceItem(
                        CredentialEvidenceItem.EvidenceType.IDENTITY_FRAUD,
                        2,
                        Collections.emptyList());

        assertTrue(Gpg45FraudValidator.validate(credentialEvidenceItem, Gpg45Profile.M1B));
    }

    @Test
    void validateShouldReturnTrueIfM1BScoresAreMetWithNullCi() {
        CredentialEvidenceItem credentialEvidenceItem =
                new CredentialEvidenceItem(
                        CredentialEvidenceItem.EvidenceType.IDENTITY_FRAUD, 2, null);

        assertTrue(Gpg45FraudValidator.validate(credentialEvidenceItem, Gpg45Profile.M1B));
    }

    @Test
    void validateShouldReturnFalseIfM1BFraudValueIsNotMet() {
        CredentialEvidenceItem credentialEvidenceItem =
                new CredentialEvidenceItem(
                        CredentialEvidenceItem.EvidenceType.IDENTITY_FRAUD,
                        1,
                        Collections.emptyList());

        assertFalse(Gpg45FraudValidator.validate(credentialEvidenceItem, Gpg45Profile.M1B));
    }

    @Test
    void validateShouldReturnFalseIfM1BScoresAreMetButHasCI() {
        CredentialEvidenceItem credentialEvidenceItem =
                new CredentialEvidenceItem(
                        CredentialEvidenceItem.EvidenceType.IDENTITY_FRAUD, 2, List.of("D02"));

        assertFalse(Gpg45FraudValidator.validate(credentialEvidenceItem, Gpg45Profile.M1B));
    }

    @Test
    void validateShouldReturnTrueIfM1BScoresAreMetButHasA01CI() {
        CredentialEvidenceItem credentialEvidenceItem =
                new CredentialEvidenceItem(
                        CredentialEvidenceItem.EvidenceType.IDENTITY_FRAUD, 2, List.of("A01"));

        assertTrue(Gpg45FraudValidator.validate(credentialEvidenceItem, Gpg45Profile.M1B));
    }
}
