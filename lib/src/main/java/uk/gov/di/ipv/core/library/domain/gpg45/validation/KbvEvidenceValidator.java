package uk.gov.di.ipv.core.library.domain.gpg45.validation;

import uk.gov.di.ipv.core.library.domain.gpg45.domain.CredentialEvidenceItem;

public class KbvEvidenceValidator {
    public static final int GPG_45_M1A_VERIFICATION_SCORE = 2;

    private KbvEvidenceValidator() {
        throw new IllegalStateException("Utility class");
    }

    public static boolean validate(CredentialEvidenceItem item) {
        return item.getVerificationScore() >= GPG_45_M1A_VERIFICATION_SCORE;
    }
}
