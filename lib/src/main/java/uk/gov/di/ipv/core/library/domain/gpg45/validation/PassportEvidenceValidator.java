package uk.gov.di.ipv.core.library.domain.gpg45.validation;

import uk.gov.di.ipv.core.library.domain.gpg45.domain.CredentialEvidenceItem;

public class PassportEvidenceValidator {
    public static final int GPG_45_M1A_STRENGTH_SCORE = 4;
    public static final int GPG_45_M1A_VALIDITY_SCORE = 2;

    private PassportEvidenceValidator() {
        throw new IllegalStateException("Utility class");
    }

    public static boolean validate(CredentialEvidenceItem item) {

        if (item.getStrengthScore() < GPG_45_M1A_STRENGTH_SCORE) {
            return false;
        }
        if (item.getValidityScore() < GPG_45_M1A_VALIDITY_SCORE) {
            return false;
        }
        return item.getCi() == null || item.getCi().isEmpty();
    }
}
