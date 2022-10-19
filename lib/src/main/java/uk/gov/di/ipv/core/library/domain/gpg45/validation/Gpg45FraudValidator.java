package uk.gov.di.ipv.core.library.domain.gpg45.validation;

import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.domain.gpg45.domain.CredentialEvidenceItem;

public class Gpg45FraudValidator {
    public static final String A01 = "A01";

    @ExcludeFromGeneratedCoverageReport
    private Gpg45FraudValidator() {
        throw new IllegalStateException("Utility class");
    }

    public static boolean isSuccessful(CredentialEvidenceItem item, boolean isFraudAllowedA01) {
        if (item.getCi() == null || item.getCi().isEmpty()) {
            return item.getIdentityFraudScore() != 0;
        } else if (item.getCi().size() == 1) {
            return isFraudAllowedA01 && item.getCi().get(0).equals(A01);
        }
        return false;
    }
}
