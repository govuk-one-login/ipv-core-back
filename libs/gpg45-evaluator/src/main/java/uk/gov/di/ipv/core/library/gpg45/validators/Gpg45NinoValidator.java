package uk.gov.di.ipv.core.library.gpg45.validators;

import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.gpg45.domain.CredentialEvidenceItem;

public class Gpg45NinoValidator {

    @ExcludeFromGeneratedCoverageReport
    private Gpg45NinoValidator() {
        throw new IllegalStateException("Utility class");
    }

    public static boolean isSuccessful(CredentialEvidenceItem item) {
        if (item.getFailedCheckDetails() != null) {
            return false;
        }
        return item.getCheckDetails() != null;
    }
}
