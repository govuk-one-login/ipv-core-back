package uk.gov.di.ipv.core.library.domain.gpg45.validation;

import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.domain.gpg45.domain.CredentialEvidenceItem;

public class Gpg45EvidenceValidator {
    @ExcludeFromGeneratedCoverageReport
    private Gpg45EvidenceValidator() {
        throw new IllegalStateException("Utility class");
    }

    public static boolean isSuccessful(CredentialEvidenceItem item) {
        if (item.getCi() == null || item.getCi().isEmpty()) {
            return item.getValidityScore() != 0;
        }
        return false;
    }
}
