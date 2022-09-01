package uk.gov.di.ipv.core.library.domain.gpg45.validation;

import uk.gov.di.ipv.core.library.domain.gpg45.Gpg45Profile;
import uk.gov.di.ipv.core.library.domain.gpg45.domain.CredentialEvidenceItem;

public class DcmawEvidenceValidator {
    public static final int GPG_45_M1B_STRENGTH_SCORE = 3;
    public static final int GPG_45_M1B_VALIDITY_SCORE = 2;

    private DcmawEvidenceValidator() {
        throw new IllegalStateException("Utility class");
    }

    public static boolean validate(CredentialEvidenceItem item, Gpg45Profile gpg45Profile) {

        if (item.getStrengthScore() < GPG_45_M1B_STRENGTH_SCORE) {
            return false;
        }
        if (item.getValidityScore() < GPG_45_M1B_VALIDITY_SCORE) {
            return false;
        }
        return item.getCi() == null || item.getCi().isEmpty();
    }
}
