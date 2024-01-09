package uk.gov.di.ipv.core.library.gpg45.validators;

import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.gpg45.domain.CredentialEvidenceItem;

public class Gpg45TicfValidator {

    @ExcludeFromGeneratedCoverageReport
    private Gpg45TicfValidator() {
        throw new IllegalStateException("Utility class");
    }

    public static boolean isSuccessful(CredentialEvidenceItem item) {
        if (item.getType().equals(CredentialEvidenceItem.TICF_EVIDENCE_TYPE)) {
            return true;
        }
        return false;
    }
}
