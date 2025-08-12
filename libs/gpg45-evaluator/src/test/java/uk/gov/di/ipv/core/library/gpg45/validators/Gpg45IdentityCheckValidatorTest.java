package uk.gov.di.ipv.core.library.gpg45.validators;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import uk.gov.di.ipv.core.library.domain.Cri;
import uk.gov.di.model.CheckDetails;
import uk.gov.di.model.IdentityCheck;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class Gpg45IdentityCheckValidatorTest {
    @ParameterizedTest
    @EnumSource(names = {"ADDRESS", "CLAIMED_IDENTITY", "TICF"})
    void isSuccessfulShouldReturnFalseForNonEvidenceCri(Cri cri) {
        var identityCheck = new IdentityCheck();
        identityCheck.setStrengthScore(4);
        identityCheck.setValidityScore(2);

        var result = Gpg45IdentityCheckValidator.isSuccessful(identityCheck, cri);

        assertFalse(result);
    }

    @ParameterizedTest
    @EnumSource(names = {"BAV", "DRIVING_LICENCE", "PASSPORT", "NINO"})
    void isSuccessfulShouldReturnTrueForValidEvidence(Cri cri) {
        var identityCheck = new IdentityCheck();
        identityCheck.setStrengthScore(4);
        identityCheck.setValidityScore(2);

        var result = Gpg45IdentityCheckValidator.isSuccessful(identityCheck, cri);

        assertTrue(result);
    }

    @ParameterizedTest
    @EnumSource(names = {"BAV", "DRIVING_LICENCE", "PASSPORT", "NINO"})
    void isSuccessfulShouldReturnFalseForEvidenceWithNoStrength(Cri cri) {
        var identityCheck = new IdentityCheck();
        identityCheck.setStrengthScore(0);
        identityCheck.setValidityScore(2);

        var result = Gpg45IdentityCheckValidator.isSuccessful(identityCheck, cri);

        assertFalse(result);
    }

    @ParameterizedTest
    @EnumSource(names = {"BAV", "DRIVING_LICENCE", "PASSPORT", "NINO"})
    void isSuccessfulShouldReturnFalseForEvidenceWithNoValidity(Cri cri) {
        var identityCheck = new IdentityCheck();
        identityCheck.setStrengthScore(4);
        identityCheck.setValidityScore(0);

        var result = Gpg45IdentityCheckValidator.isSuccessful(identityCheck, cri);

        assertFalse(result);
    }

    @ParameterizedTest
    @EnumSource(names = {"EXPERIAN_FRAUD"})
    void isSuccessfulShouldReturnTrueForFraudCheckWithFraudScore(Cri cri) {
        var identityCheck = new IdentityCheck();
        identityCheck.setIdentityFraudScore(2);

        var result = Gpg45IdentityCheckValidator.isSuccessful(identityCheck, cri);

        assertTrue(result);
    }

    @ParameterizedTest
    @EnumSource(names = {"EXPERIAN_FRAUD"})
    void isSuccessfulShouldReturnFalseForFraudCheckWithNoFraudScore(Cri cri) {
        var identityCheck = new IdentityCheck();
        identityCheck.setIdentityFraudScore(0);

        var result = Gpg45IdentityCheckValidator.isSuccessful(identityCheck, cri);

        assertFalse(result);
    }

    @ParameterizedTest
    @EnumSource(names = {"DWP_KBV", "EXPERIAN_KBV"})
    void isSuccessfulShouldReturnTrueForKbvWithVerificationScore(Cri cri) {
        var identityCheck = new IdentityCheck();
        identityCheck.setVerificationScore(2);

        var result = Gpg45IdentityCheckValidator.isSuccessful(identityCheck, cri);

        assertTrue(result);
    }

    @ParameterizedTest
    @EnumSource(names = {"DWP_KBV", "EXPERIAN_KBV"})
    void isSuccessfulShouldReturnFalseForKbvWithNoVerificationScore(Cri cri) {
        var identityCheck = new IdentityCheck();
        identityCheck.setVerificationScore(0);

        var result = Gpg45IdentityCheckValidator.isSuccessful(identityCheck, cri);

        assertFalse(result);
    }

    @ParameterizedTest
    @EnumSource(names = {"DCMAW", "DCMAW_ASYNC", "F2F"})
    void isSuccessfulShouldReturnTrueForCombinedDocVerificationWithValidEvidence(Cri cri) {
        var identityCheck = new IdentityCheck();
        identityCheck.setStrengthScore(4);
        identityCheck.setValidityScore(2);
        var checkDetails = new CheckDetails();
        checkDetails.setCheckMethod(CheckDetails.CheckMethodType.BVR);
        checkDetails.setBiometricVerificationProcessLevel(2);
        identityCheck.setCheckDetails(List.of(checkDetails));

        var result = Gpg45IdentityCheckValidator.isSuccessful(identityCheck, cri);

        assertTrue(result);
    }

    @ParameterizedTest
    @EnumSource(names = {"DCMAW", "DCMAW_ASYNC", "F2F"})
    void isSuccessfulShouldReturnFalseForCombinedDocVerificationWithNoStrength(Cri cri) {
        var identityCheck = new IdentityCheck();
        identityCheck.setStrengthScore(0);
        identityCheck.setValidityScore(2);
        var checkDetails = new CheckDetails();
        checkDetails.setCheckMethod(CheckDetails.CheckMethodType.BVR);
        checkDetails.setBiometricVerificationProcessLevel(2);
        identityCheck.setCheckDetails(List.of(checkDetails));

        var result = Gpg45IdentityCheckValidator.isSuccessful(identityCheck, cri);

        assertFalse(result);
    }

    @ParameterizedTest
    @EnumSource(names = {"DCMAW", "DCMAW_ASYNC", "F2F"})
    void isSuccessfulShouldReturnFalseForCombinedDocVerificationWithNoValidity(Cri cri) {
        var identityCheck = new IdentityCheck();
        identityCheck.setStrengthScore(4);
        identityCheck.setValidityScore(0);
        var checkDetails = new CheckDetails();
        checkDetails.setCheckMethod(CheckDetails.CheckMethodType.BVR);
        checkDetails.setBiometricVerificationProcessLevel(2);
        identityCheck.setCheckDetails(List.of(checkDetails));

        var result = Gpg45IdentityCheckValidator.isSuccessful(identityCheck, cri);

        assertFalse(result);
    }

    @ParameterizedTest
    @EnumSource(names = {"DCMAW", "DCMAW_ASYNC", "F2F"})
    void isSuccessfulShouldReturnFalseForCombinedDocVerificationWithNoBiometricVerification(
            Cri cri) {
        var identityCheck = new IdentityCheck();
        identityCheck.setStrengthScore(4);
        identityCheck.setValidityScore(2);
        var checkDetails = new CheckDetails();
        checkDetails.setCheckMethod(CheckDetails.CheckMethodType.BVR);
        checkDetails.setBiometricVerificationProcessLevel(0);
        identityCheck.setFailedCheckDetails(List.of(checkDetails));

        var result = Gpg45IdentityCheckValidator.isSuccessful(identityCheck, cri);

        assertFalse(result);
    }

    @Test
    void isSuccessfulShouldReturnTrueForNinoWithNoScores() {
        var identityCheck = new IdentityCheck();

        var result = Gpg45IdentityCheckValidator.isSuccessful(identityCheck, Cri.NINO);

        assertTrue(result);
    }

    @Test
    void isSuccessfulShouldReturnFalseForNinoWithNoScoresAndFailedCheck() {
        var identityCheck = new IdentityCheck();
        identityCheck.setFailedCheckDetails(List.of(new CheckDetails()));

        var result = Gpg45IdentityCheckValidator.isSuccessful(identityCheck, Cri.NINO);

        assertFalse(result);
    }
}
