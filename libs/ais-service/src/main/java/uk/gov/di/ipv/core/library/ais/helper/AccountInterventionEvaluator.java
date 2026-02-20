package uk.gov.di.ipv.core.library.ais.helper;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.ipv.core.library.dto.AccountInterventionState;
import uk.gov.di.ipv.core.library.enums.TicfCode;
import uk.gov.di.ipv.core.library.helpers.LogHelper;

import static uk.gov.di.ipv.core.library.enums.TicfCode.ACCOUNT_UNBLOCKED;
import static uk.gov.di.ipv.core.library.enums.TicfCode.ACCOUNT_UNSUSPENDED;
import static uk.gov.di.ipv.core.library.enums.TicfCode.FORCED_USER_IDENTITY_VERIFY;
import static uk.gov.di.ipv.core.library.enums.TicfCode.NO_INTERVENTION;

public final class AccountInterventionEvaluator {

    private static final Logger LOGGER = LogManager.getLogger();
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final String OBJECT_MAPPING_ERROR_MESSAGE =
            "Error converting account intervention state to string";

    private AccountInterventionEvaluator() {
        // prevent initialisation
    }

    private static boolean isNotACurrentIntervention(TicfCode ticfInterventionType) {
        return NO_INTERVENTION.equals(ticfInterventionType)
                || ACCOUNT_UNBLOCKED.equals(ticfInterventionType)
                || ACCOUNT_UNSUSPENDED.equals(ticfInterventionType);
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
            LOGGER.error(LogHelper.buildErrorMessage(OBJECT_MAPPING_ERROR_MESSAGE, e));
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
            LOGGER.error(LogHelper.buildErrorMessage(OBJECT_MAPPING_ERROR_MESSAGE, e));
            LOGGER.info(LogHelper.buildLogMessage("Mid journey intervention detected."));
        }
        return true;
    }

    public static boolean hasTicfIntervention(
            AccountInterventionState currentAisState, TicfCode ticfIntervention) {
        var bothValid =
                hasNoInterventionFlag(currentAisState)
                        && isNotACurrentIntervention(ticfIntervention);
        var bothReprove =
                isReprove(currentAisState) && FORCED_USER_IDENTITY_VERIFY.equals(ticfIntervention);
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
            LOGGER.error(LogHelper.buildErrorMessage(OBJECT_MAPPING_ERROR_MESSAGE, e));
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
