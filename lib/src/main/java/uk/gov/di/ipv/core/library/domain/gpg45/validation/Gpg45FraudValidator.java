package uk.gov.di.ipv.core.library.domain.gpg45.validation;

import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.domain.gpg45.domain.CredentialEvidenceItem;

public class Gpg45FraudValidator {
    public static final String A01 = "A01";

    @ExcludeFromGeneratedCoverageReport
    private Gpg45FraudValidator() {
        throw new IllegalStateException("Utility class");
    }

    public static boolean isSuccessful(CredentialEvidenceItem item) {
        return item.getIdentityFraudScore() != 0;
    }
}
