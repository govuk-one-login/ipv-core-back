package uk.gov.di.ipv.core.library.gpg45.validators;

import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.gpg45.domain.CheckDetail;
import uk.gov.di.ipv.core.library.gpg45.domain.CredentialEvidenceItem;

import java.util.List;

public class Gpg45DcmawValidator {
    @ExcludeFromGeneratedCoverageReport
    private Gpg45DcmawValidator() {
        throw new IllegalStateException("Utility class");
    }

    public static boolean isSuccessful(CredentialEvidenceItem item) {
        if (item.getFailedCheckDetails() != null) {
            return false;
        }

        return item.getValidityScore() != 0
                && getDcmawVerificationScore(item.getCheckDetails()) > 0
                && item.getStrengthScore() > 0;
    }

    private static Integer getDcmawVerificationScore(List<CheckDetail> checkMethods) {
        var checkMethodWithVerificationScore =
                checkMethods.stream()
                        .filter(
                                checkMethod ->
                                        checkMethod.getBiometricVerificationProcessLevel() != null)
                        .findFirst();

        return checkMethodWithVerificationScore.isPresent()
                ? checkMethodWithVerificationScore.get().getBiometricVerificationProcessLevel()
                : 0;
    }
}
