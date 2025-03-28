package uk.gov.di.ipv.core.library.gpg45.validators;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.domain.Cri;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.model.IdentityCheck;

import static software.amazon.awssdk.utils.CollectionUtils.isNullOrEmpty;
import static uk.gov.di.ipv.core.library.gpg45.Gpg45ProfileEvaluator.getVerificationScore;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_CRI_ID;

public class Gpg45IdentityCheckValidator {
    private static final Logger LOGGER = LogManager.getLogger();

    @ExcludeFromGeneratedCoverageReport
    private Gpg45IdentityCheckValidator() {
        throw new IllegalStateException("Utility class");
    }

    public static boolean isSuccessful(IdentityCheck identityCheck, Cri cri) {
        return switch (cri) {
            case BAV, DRIVING_LICENCE, PASSPORT -> isEvidenceSuccessful(identityCheck);
            case EXPERIAN_FRAUD -> isFraudCheckSuccessful(identityCheck);
            case DWP_KBV, EXPERIAN_KBV -> isVerificationSuccessful(identityCheck);
            case DCMAW, DCMAW_ASYNC, F2F, HMRC_MIGRATION ->
                    isEvidenceSuccessful(identityCheck) && isVerificationSuccessful(identityCheck);
            case NINO -> isNinoSuccessful(identityCheck);
            case ADDRESS, CIMIT, CLAIMED_IDENTITY, TICF -> {
                LOGGER.warn(
                        LogHelper.buildLogMessage("Unexpected IdentityCheck from non-evidence CRI")
                                .with(LOG_CRI_ID.name(), cri.getId()));
                yield false;
            }
        };
    }

    private static boolean isEvidenceSuccessful(IdentityCheck identityCheck) {
        return isPositiveScore(identityCheck.getStrengthScore())
                && isPositiveScore(identityCheck.getValidityScore());
    }

    private static boolean isVerificationSuccessful(IdentityCheck identityCheck) {
        return isPositiveScore(getVerificationScore(identityCheck));
    }

    private static boolean isFraudCheckSuccessful(IdentityCheck identityCheck) {
        return isPositiveScore(identityCheck.getIdentityFraudScore());
    }

    // NINO is a special case - sometimes it won't provide any GPG45 scores
    // but we still want to check for success
    private static boolean isNinoSuccessful(IdentityCheck identityCheck) {
        return isEvidenceSuccessful(identityCheck)
                || (isNullOrEmpty(identityCheck.getFailedCheckDetails())
                        && identityCheck.getStrengthScore() == null
                        && identityCheck.getValidityScore() == null);
    }

    private static boolean isPositiveScore(Integer score) {
        return score != null && score > 0;
    }
}
