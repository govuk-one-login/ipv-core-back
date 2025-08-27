package uk.gov.di.ipv.core.library.ais.helper;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.ipv.core.library.domain.AisInterventionType;
import uk.gov.di.ipv.core.library.helpers.LogHelper;

import static uk.gov.di.ipv.core.library.domain.AisInterventionType.*;
import static uk.gov.di.ipv.core.library.domain.AisInterventionType.AIS_FORCED_USER_IDENTITY_VERIFY;

public final class AccountInterventionEvaluator {

    private static final Logger LOGGER = LogManager.getLogger();

    private AccountInterventionEvaluator() {
        // prevent initialisation
    }

    public static boolean isStartOfJourneyInterventionDetected(
            AisInterventionType interventionType) {
        if (isValidIntervention(interventionType)
                || AIS_FORCED_USER_IDENTITY_VERIFY.equals(interventionType)) {
            return false;
        }

        LogHelper.buildLogMessage(
                "Intervention detected at the start of the journey. Intervention type: %s"
                        .formatted(interventionType));

        return true;
    }

    public static boolean isMidOfJourneyInterventionDetected(
            AisInterventionType initial, AisInterventionType current) {

        var bothValid = isValidIntervention(initial) && isValidIntervention(current);
        var bothReprove = isBothIdentityVerify(initial, current);
        var reproveToValid = isIdentityVerifyToValid(initial, current);

        if (bothValid || bothReprove || reproveToValid) {
            return false;
        }

        LOGGER.info(
                LogHelper.buildLogMessage(
                        "Mid journey intervention detected. Initial intervention: %s Final intervention: %s"
                                .formatted(initial, current)));
        return true;
    }

    private static boolean isBothIdentityVerify(
            AisInterventionType initial, AisInterventionType current) {
        return AIS_FORCED_USER_IDENTITY_VERIFY.equals(initial)
                && AIS_FORCED_USER_IDENTITY_VERIFY.equals(current);
    }

    private static boolean isIdentityVerifyToValid(
            AisInterventionType initial, AisInterventionType current) {
        return AIS_FORCED_USER_IDENTITY_VERIFY.equals(initial) && isValidIntervention(current);
    }

    private static boolean isValidIntervention(AisInterventionType aisInterventionType) {
        return AIS_NO_INTERVENTION.equals(aisInterventionType)
                || AIS_ACCOUNT_UNBLOCKED.equals(aisInterventionType)
                || AIS_ACCOUNT_UNSUSPENDED.equals(aisInterventionType);
    }
}
