package uk.gov.di.ipv.core.library.domain.gpg45.validation;

import uk.gov.di.ipv.core.library.domain.gpg45.Gpg45Profile;
import uk.gov.di.ipv.core.library.domain.gpg45.domain.CredentialEvidenceItem;

public class KbvEvidenceValidator {
    private KbvEvidenceValidator() {
        throw new IllegalStateException("Utility class");
    }

    public static boolean validate(CredentialEvidenceItem item, Gpg45Profile gpg45Profile) {
        return item.getVerificationScore() >= gpg45Profile.scores.verification();
    }
}
