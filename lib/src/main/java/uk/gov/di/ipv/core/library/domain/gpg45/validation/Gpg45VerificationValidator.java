package uk.gov.di.ipv.core.library.domain.gpg45.validation;

import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.domain.gpg45.domain.CredentialEvidenceItem;

public class Gpg45VerificationValidator {
    @ExcludeFromGeneratedCoverageReport
    private Gpg45VerificationValidator() {
        throw new IllegalStateException("Utility class");
    }

    public static boolean isSuccessful(CredentialEvidenceItem item) {
        if (item.getCi() == null || item.getCi().isEmpty()) {
            return item.getVerificationScore() != 0;
        }
        return false;
    }
}
