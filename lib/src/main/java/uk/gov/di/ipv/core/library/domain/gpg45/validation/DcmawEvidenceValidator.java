package uk.gov.di.ipv.core.library.domain.gpg45.validation;

import uk.gov.di.ipv.core.library.domain.gpg45.Gpg45Profile;
import uk.gov.di.ipv.core.library.domain.gpg45.domain.CredentialEvidenceItem;

public class DcmawEvidenceValidator {
    private DcmawEvidenceValidator() {
        throw new IllegalStateException("Utility class");
    }

    public static boolean validate(CredentialEvidenceItem item, Gpg45Profile gpg45Profile) {

        if (item.getStrengthScore() < gpg45Profile.scores.evidences().get(0).strength()) {
            return false;
        }
        if (item.getValidityScore() < gpg45Profile.scores.evidences().get(0).validity()) {
            return false;
        }
        return item.getCi() == null || item.getCi().isEmpty();
    }
}
