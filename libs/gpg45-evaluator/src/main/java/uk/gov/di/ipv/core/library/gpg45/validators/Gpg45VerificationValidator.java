package uk.gov.di.ipv.core.library.gpg45.validators;

import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.domain.CredentialEvidenceItem;

public class Gpg45VerificationValidator {
    @ExcludeFromGeneratedCoverageReport
    private Gpg45VerificationValidator() {
        throw new IllegalStateException("Utility class");
    }

    public static boolean isSuccessful(CredentialEvidenceItem item) {
        return item.getVerificationScore() != 0;
    }
}
