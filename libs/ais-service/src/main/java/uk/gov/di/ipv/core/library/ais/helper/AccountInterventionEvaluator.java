package uk.gov.di.ipv.core.library.ais.helper;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.ipv.core.library.domain.AisInterventionType;
import uk.gov.di.ipv.core.library.helpers.LogHelper;

import static uk.gov.di.ipv.core.library.domain.AisInterventionType.AIS_ACCOUNT_UNBLOCKED;
import static uk.gov.di.ipv.core.library.domain.AisInterventionType.AIS_ACCOUNT_UNSUSPENDED;
import static uk.gov.di.ipv.core.library.domain.AisInterventionType.AIS_FORCED_USER_IDENTITY_VERIFY;
import static uk.gov.di.ipv.core.library.domain.AisInterventionType.AIS_NO_INTERVENTION;

public final class AccountInterventionEvaluator {

    private static final Logger LOGGER = LogManager.getLogger();

    private AccountInterventionEvaluator() {
        // prevent initialisation
    }

    public static boolean hasStartOfJourneyIntervention(AisInterventionType interventionType) {
        if (isValidIntervention(interventionType)
                || AIS_FORCED_USER_IDENTITY_VERIFY.equals(interventionType)) {
            return false;
        }

        LogHelper.buildLogMessage(
                "Intervention detected at the start of the journey. Intervention type: %s"
                        .formatted(interventionType));

        return true;
    }

    public static boolean hasMidJourneyIntervention(
            boolean isReproveIdentity, AisInterventionType aisInterventionType) {

        var bothReprove =
                isReproveIdentity && AIS_FORCED_USER_IDENTITY_VERIFY.equals(aisInterventionType);
        var reproveToValid = isReproveIdentity && isValidIntervention(aisInterventionType);
        var isValid = isValidIntervention(aisInterventionType);

        if (bothReprove || reproveToValid || isValid) {
            return false;
        }

        LOGGER.info(
                LogHelper.buildLogMessage(
                        "Mid journey intervention detected. Intervention type: %s"
                                .formatted(aisInterventionType)));
        return true;
    }

    public static boolean hasTicfIntervention(
            AisInterventionType currentIntervention, AisInterventionType ticfIntervention) {

        var bothValid =
                isValidIntervention(currentIntervention) && isValidIntervention(ticfIntervention);
        var bothReprove = isBothIdentityVerify(currentIntervention, ticfIntervention);
        var reproveToValid = isIdentityVerifyToValid(currentIntervention, ticfIntervention);

        if (bothValid || bothReprove || reproveToValid) {
            return false;
        }

        LOGGER.info(
                LogHelper.buildLogMessage(
                        "TICF intervention detected. Current intervention: %s TICF intervention: %s"
                                .formatted(currentIntervention, ticfIntervention)));
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
