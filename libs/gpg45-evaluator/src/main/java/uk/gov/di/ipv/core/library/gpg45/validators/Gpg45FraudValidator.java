package uk.gov.di.ipv.core.library.gpg45.validators;

import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.domain.CredentialEvidenceItem;

public class Gpg45FraudValidator {

    @ExcludeFromGeneratedCoverageReport
    private Gpg45FraudValidator() {
        throw new IllegalStateException("Utility class");
    }

    public static boolean isSuccessful(CredentialEvidenceItem item) {
        return item.getIdentityFraudScore() != 0;
    }
}
