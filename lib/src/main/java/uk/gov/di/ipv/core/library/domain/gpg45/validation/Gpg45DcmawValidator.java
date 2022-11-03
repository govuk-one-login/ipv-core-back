package uk.gov.di.ipv.core.library.domain.gpg45.validation;

import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.domain.ContraIndicatorScores;
import uk.gov.di.ipv.core.library.domain.gpg45.domain.CredentialEvidenceItem;
import uk.gov.di.ipv.core.library.helpers.VcHelper;

import java.util.Map;

public class Gpg45DcmawValidator {
    @ExcludeFromGeneratedCoverageReport
    private Gpg45DcmawValidator() {
        throw new IllegalStateException("Utility class");
    }

    public static boolean isSuccessful(
            CredentialEvidenceItem item,
            Map<String, ContraIndicatorScores> ciScoresMap,
            int ciScoreThreshold) {
        if (item.getFailedCheckDetails() != null) {
            return false;
        }
        if (item.getValidityScore() != 0) {
            if (item.getCi() == null || item.getCi().isEmpty()) {
                return true;
            } else {
                return VcHelper.calculateCiScore(item.getCi(), ciScoresMap) <= ciScoreThreshold;
            }
        }
        return false;
    }
}
