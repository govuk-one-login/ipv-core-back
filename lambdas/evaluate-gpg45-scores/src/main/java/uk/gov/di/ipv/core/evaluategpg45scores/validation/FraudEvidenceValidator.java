package uk.gov.di.ipv.core.evaluategpg45scores.validation;

import uk.gov.di.ipv.core.evaluategpg45scores.domain.CredentialEvidenceItem;

public class FraudEvidenceValidator {
    public static final int GPG_45_M1A_FRAUD_SCORE = 1;

    private FraudEvidenceValidator() {
        throw new IllegalStateException("Utility class");
    }

    public static boolean validate(CredentialEvidenceItem item) {
        if (item.getIdentityFraudScore() < GPG_45_M1A_FRAUD_SCORE) {
            return false;
        }
        return item.getCi() == null || item.getCi().isEmpty();
    }
}
