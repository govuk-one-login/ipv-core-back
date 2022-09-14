package uk.gov.di.ipv.core.library.domain.gpg45.validation;

import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.domain.gpg45.domain.CredentialEvidenceItem;

public class Gpg45DcmawValidator {
    @ExcludeFromGeneratedCoverageReport
    private Gpg45DcmawValidator() {
        throw new IllegalStateException("Utility class");
    }

    public static boolean isSuccessful(CredentialEvidenceItem item) {
        if (item.getFailedCheckDetails() != null) {
            return false;
        }

        return item.getValidityScore() != 0;
    }
}
