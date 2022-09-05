package uk.gov.di.ipv.core.library.domain.gpg45.validation;

import uk.gov.di.ipv.core.library.domain.gpg45.domain.CredentialEvidenceItem;

import java.util.List;

public class FraudEvidenceValidator {
    public static final int GPG_45_M1A_FRAUD_SCORE = 1;
    public static final String A01 = "A01";

    private FraudEvidenceValidator() {
        throw new IllegalStateException("Utility class");
    }

    public static boolean validate(CredentialEvidenceItem item) {
        if (item.getIdentityFraudScore() < GPG_45_M1A_FRAUD_SCORE) {
            return false;
        }
        List<String> ciList = item.getCi();
        return ciList == null
                || ciList.isEmpty()
                || (ciList.size() == 1 && ciList.get(0).equals(A01));
    }
}
