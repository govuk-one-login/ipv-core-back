package uk.gov.di.ipv.core.library.ais.helper;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.ipv.core.library.domain.AisInterventionType;
import uk.gov.di.ipv.core.library.dto.AccountInterventionState;
import uk.gov.di.ipv.core.library.helpers.LogHelper;

import static uk.gov.di.ipv.core.library.domain.AisInterventionType.AIS_ACCOUNT_UNBLOCKED;
import static uk.gov.di.ipv.core.library.domain.AisInterventionType.AIS_ACCOUNT_UNSUSPENDED;
import static uk.gov.di.ipv.core.library.domain.AisInterventionType.AIS_FORCED_USER_IDENTITY_VERIFY;
import static uk.gov.di.ipv.core.library.domain.AisInterventionType.AIS_NO_INTERVENTION;

public final class AccountInterventionEvaluator {

    private static final Logger LOGGER = LogManager.getLogger();
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    private AccountInterventionEvaluator() {
        // prevent initialisation
    }

    public static boolean hasStartOfJourneyIntervention(AisInterventionType interventionType) {
        if (isNotACurrentIntervention(interventionType)
                || AIS_FORCED_USER_IDENTITY_VERIFY.equals(interventionType)) {
            return false;
        }

        LOGGER.info(
                LogHelper.buildLogMessage(
                        "Intervention detected at the start of the journey. Intervention type: %s"
                                .formatted(interventionType)));

        return true;
    }

    public static boolean hasMidJourneyIntervention(
            boolean isReproveIdentity, AisInterventionType aisInterventionType) {

        var bothReprove =
                isReproveIdentity && AIS_FORCED_USER_IDENTITY_VERIFY.equals(aisInterventionType);
        var reproveToValid = isReproveIdentity && isNotACurrentIntervention(aisInterventionType);
        var isValid = isNotACurrentIntervention(aisInterventionType);

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
                isNotACurrentIntervention(currentIntervention)
                        && isNotACurrentIntervention(ticfIntervention);
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
        return AIS_FORCED_USER_IDENTITY_VERIFY.equals(initial)
                && isNotACurrentIntervention(current);
    }

    private static boolean isNotACurrentIntervention(AisInterventionType aisInterventionType) {
        return AIS_NO_INTERVENTION.equals(aisInterventionType)
                || AIS_ACCOUNT_UNBLOCKED.equals(aisInterventionType)
                || AIS_ACCOUNT_UNSUSPENDED.equals(aisInterventionType);
    }

    public static boolean hasStartOfJourneyIntervention(AccountInterventionState aisState) {
        var noIntervention = hasNoInterventionFlag(aisState);
        var isReprove = isReprove(aisState);

        if (noIntervention || isReprove) {
            return false;
        }

        try {
            LOGGER.info(
                    LogHelper.buildLogMessage(
                            "Start of journey intervention detected. Intervention state: %s"
                                    .formatted(OBJECT_MAPPER.writeValueAsString(aisState))));
        } catch (JsonProcessingException e) {
            LOGGER.error(
                    LogHelper.buildErrorMessage(
                            "Error converting account intervention state to string", e));
            LOGGER.info(LogHelper.buildLogMessage("Start of journey intervention detected."));
        }
        return true;
    }

    public static boolean hasMidJourneyIntervention(
            boolean isReproveIdentity, AccountInterventionState currentAccountInterventionState) {
        var noAisIntervention = hasNoInterventionFlag(currentAccountInterventionState);
        // If the user is currently reproving their identity then the suspended and reprove identity
        // flags may not have been reset yet.
        var bothReprove = isReproveIdentity && isReprove(currentAccountInterventionState);

        if (noAisIntervention || bothReprove) {
            return false;
        }

        // Otherwise an intervention flag has been set for some other reason
        try {
            LOGGER.info(
                    LogHelper.buildLogMessage(
                            "Mid journey intervention detected. Is reprove: %s AIS state: %s"
                                    .formatted(
                                            isReproveIdentity,
                                            OBJECT_MAPPER.writeValueAsString(
                                                    currentAccountInterventionState))));
        } catch (JsonProcessingException e) {
            LOGGER.error(
                    LogHelper.buildErrorMessage(
                            "Error converting account intervention state to string", e));
            LOGGER.info(LogHelper.buildLogMessage("Mid journey intervention detected."));
        }
        return true;
    }

    public static boolean hasTicfIntervention(
            AccountInterventionState currentAisState, AisInterventionType ticfIntervention) {
        var bothValid =
                hasNoInterventionFlag(currentAisState)
                        && isNotACurrentIntervention(ticfIntervention);
        var bothReprove =
                isReprove(currentAisState)
                        && AIS_FORCED_USER_IDENTITY_VERIFY.equals(ticfIntervention);
        var reproveToValid =
                isReprove(currentAisState) && isNotACurrentIntervention(ticfIntervention);

        if (bothValid || bothReprove || reproveToValid) {
            return false;
        }

        try {
            LOGGER.info(
                    LogHelper.buildLogMessage(
                            "TICF intervention detected. Current intervention: %s TICF intervention: %s"
                                    .formatted(
                                            OBJECT_MAPPER.writeValueAsString(currentAisState),
                                            ticfIntervention)));
        } catch (JsonProcessingException e) {
            LOGGER.error(
                    LogHelper.buildErrorMessage(
                            "Error converting account intervention state to string", e));
            LOGGER.info(LogHelper.buildLogMessage("TICF intervention detected."));
        }

        return true;
    }

    private static boolean hasNoInterventionFlag(
            AccountInterventionState accountInterventionState) {
        return !accountInterventionState.isResetPassword()
                && !accountInterventionState.isBlocked()
                && !accountInterventionState.isReproveIdentity()
                && !accountInterventionState.isSuspended();
    }

    public static boolean isReprove(AccountInterventionState accountInterventionState) {
        // The suspended flag should be set whenever the reproveIdentity flag is set, but if it
        // isn't for any reason we should still treat the state as reprove, so we don't check the
        // suspended flag here.
        return !accountInterventionState.isResetPassword()
                && !accountInterventionState.isBlocked()
                && accountInterventionState.isReproveIdentity();
    }
}
