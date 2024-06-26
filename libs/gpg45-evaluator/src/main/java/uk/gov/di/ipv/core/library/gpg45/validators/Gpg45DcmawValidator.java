package uk.gov.di.ipv.core.library.gpg45.validators;

import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.gpg45.domain.CredentialEvidenceItem;

public class Gpg45DcmawValidator {
    @ExcludeFromGeneratedCoverageReport
    private Gpg45DcmawValidator() {
        throw new IllegalStateException("Utility class");
    }

    public static boolean isSuccessful(CredentialEvidenceItem item) {
        if (item.getFailedCheckDetails() != null) {
            return false;
        }

        // PYIC-3907 This should also check strength and verification scores
        return item.getValidityScore() != 0;
    }
}
