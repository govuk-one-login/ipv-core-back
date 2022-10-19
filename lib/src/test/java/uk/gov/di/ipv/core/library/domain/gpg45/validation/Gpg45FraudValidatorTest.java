package uk.gov.di.ipv.core.library.domain.gpg45.validation;

import org.junit.jupiter.api.Test;
import uk.gov.di.ipv.core.library.domain.gpg45.domain.CredentialEvidenceItem;

import java.util.Collections;
import java.util.List;

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

        assertTrue(Gpg45FraudValidator.isSuccessful(credentialEvidenceItem, true));
    }

    @Test
    void isSuccessfulShouldReturnTrueOnValidCredentialAndNullCi() {
        CredentialEvidenceItem credentialEvidenceItem =
                new CredentialEvidenceItem(
                        CredentialEvidenceItem.EvidenceType.IDENTITY_FRAUD, 2, null);

        assertTrue(Gpg45FraudValidator.isSuccessful(credentialEvidenceItem, true));
    }

    @Test
    void isSuccessfulShouldReturnFalseOnValidCredential() {
        CredentialEvidenceItem credentialEvidenceItem =
                new CredentialEvidenceItem(
                        CredentialEvidenceItem.EvidenceType.IDENTITY_FRAUD,
                        0,
                        Collections.emptyList());

        assertFalse(Gpg45FraudValidator.isSuccessful(credentialEvidenceItem, true));
    }

    @Test
    void isSuccessfulShouldReturnTrueOnValidCredentialWithA01AndAllowed() {
        CredentialEvidenceItem credentialEvidenceItem =
                new CredentialEvidenceItem(
                        CredentialEvidenceItem.EvidenceType.IDENTITY_FRAUD, 0, List.of("A01"));

        assertTrue(Gpg45FraudValidator.isSuccessful(credentialEvidenceItem, true));
    }

    @Test
    void isSuccessfulShouldReturnFalseOnValidCredentialWithA01AndNotAllowed() {
        CredentialEvidenceItem credentialEvidenceItem =
                new CredentialEvidenceItem(
                        CredentialEvidenceItem.EvidenceType.IDENTITY_FRAUD, 0, List.of("A01"));

        assertFalse(Gpg45FraudValidator.isSuccessful(credentialEvidenceItem, false));
    }

    @Test
    void isSuccessfulShouldReturnFalseOnValidCredentialWithMultipleCI() {
        CredentialEvidenceItem credentialEvidenceItem =
                new CredentialEvidenceItem(
                        CredentialEvidenceItem.EvidenceType.IDENTITY_FRAUD,
                        0,
                        List.of("A01", "D02"));

        assertFalse(Gpg45FraudValidator.isSuccessful(credentialEvidenceItem, false));
    }
}
