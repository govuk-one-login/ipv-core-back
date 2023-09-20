package uk.gov.di.ipv.core.library.gpg45.validators;

import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.domain.CredentialEvidenceItem;

public class Gpg45EvidenceValidator {
    @ExcludeFromGeneratedCoverageReport
    private Gpg45EvidenceValidator() {
        throw new IllegalStateException("Utility class");
    }

    public static boolean isSuccessful(CredentialEvidenceItem item) {
        return item.getValidityScore() != 0;
    }
}
