package uk.gov.di.ipv.core.library.domain.gpg45.validation;

import uk.gov.di.ipv.core.library.domain.gpg45.Gpg45Profile;
import uk.gov.di.ipv.core.library.domain.gpg45.domain.CredentialEvidenceItem;

import java.util.List;

public class FraudEvidenceValidator {
    public static final String A01 = "A01";

    private FraudEvidenceValidator() {
        throw new IllegalStateException("Utility class");
    }

    public static boolean validate(CredentialEvidenceItem item, Gpg45Profile gpg45Profile) {
        if (item.getIdentityFraudScore() < gpg45Profile.scores.fraud()) {
            return false;
        }
        List<String> ciList = item.getCi();
        return ciList == null
                || ciList.isEmpty()
                || (ciList.size() == 1 && ciList.get(0).equals(A01));
    }
}
