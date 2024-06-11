package uk.gov.di.ipv.core.library.gpg45.validators;

import org.junit.jupiter.api.Test;
import uk.gov.di.ipv.core.library.gpg45.domain.CheckDetail;
import uk.gov.di.ipv.core.library.gpg45.domain.CredentialEvidenceItem;

import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class Gpg45DcmawValidatorTest {

    @Test
    void isSuccessfulShouldReturnTrueOnValidCredential() {
        var testCheckDetail = new CheckDetail();
        testCheckDetail.setBiometricVerificationProcessLevel(2);

        CredentialEvidenceItem credentialEvidenceItem =
                new CredentialEvidenceItem(
                        3,
                        2,
                        1,
                        2,
                        Collections.singletonList(testCheckDetail),
                        null,
                        Collections.emptyList());

        assertTrue(Gpg45DcmawValidator.isSuccessful(credentialEvidenceItem));
    }

    @Test
    void isSuccessfulShouldReturnFalseOnInvalidCredentialWithNoBiometricVerificationProcessLevel() {
        CredentialEvidenceItem credentialEvidenceItem =
                new CredentialEvidenceItem(
                        3,
                        2,
                        1,
                        2,
                        Collections.singletonList(new CheckDetail()),
                        null,
                        Collections.emptyList());

        assertFalse(Gpg45DcmawValidator.isSuccessful(credentialEvidenceItem));
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

    @Test
    void getDcmawVerificationScoreReturnsZeroForNullCheckMethods() {
        var verificationScore = Gpg45DcmawValidator.getDcmawVerificationScore(null);

        assertEquals(0, verificationScore);
    }

    @Test
    void getDcmawVerificationScoreReturnsZeroWhenNoBiometricVerificationProcessLevelExists() {
        var checkDetailsNoBiometricVerificationProcessLevel = List.of(new CheckDetail());
        var verificationScore =
                Gpg45DcmawValidator.getDcmawVerificationScore(
                        checkDetailsNoBiometricVerificationProcessLevel);

        assertEquals(0, verificationScore);
    }

    @Test
    void getDcmawVerificationScoreReturnsScoreWhenBiometricVerificationProcessLevelIsPresent() {}

    {
        CheckDetail checkDetail = new CheckDetail();
        checkDetail.setBiometricVerificationProcessLevel(3);

        var verificationScore = Gpg45DcmawValidator.getDcmawVerificationScore(List.of(checkDetail));

        assertEquals(3, verificationScore);
    }
}
