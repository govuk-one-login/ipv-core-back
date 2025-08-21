package uk.gov.di.ipv.core.library.ais.helper;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.ipv.core.library.dto.AccountInterventionState;
import uk.gov.di.ipv.core.library.helpers.LogHelper;

public final class AccountInterventionEvaluator {

    private static final Logger LOGGER = LogManager.getLogger();
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    private AccountInterventionEvaluator() {
        // prevent initialisation
    }

    public static boolean isInitialAccountInterventionDetected(
            AccountInterventionState initialAccountInterventionState) {
        // if no flags are set then there is no intervention
        if (hasNoInterventionFlag(initialAccountInterventionState)) {
            return false;
        }

        // we allow user to proceed to reverify journey
        if (!initialAccountInterventionState.isBlocked()
                && !initialAccountInterventionState.isResetPassword()
                && initialAccountInterventionState.isSuspended()
                && initialAccountInterventionState.isReproveIdentity()) {
            return false;
        }

        if (!initialAccountInterventionState.isBlocked()
                && !initialAccountInterventionState.isResetPassword()
                && !initialAccountInterventionState.isSuspended()) {
            return false;
        }

        try {
            LOGGER.info(
                    LogHelper.buildLogMessage(
                            "Intervention detected at the start of the journey. Initial state: %s"
                                    .formatted(
                                            OBJECT_MAPPER.writeValueAsString(
                                                    initialAccountInterventionState))));
        } catch (JsonProcessingException e) {
            LOGGER.error(
                    LogHelper.buildErrorMessage(
                            "Error converting account intervention state to string", e));
            LOGGER.info(LogHelper.buildLogMessage("Initial journey intervention detected."));
        }

        return true;
    }

    public static boolean isMidJourneyAccountInterventionDetected(
            AccountInterventionState initialAccountInterventionState,
            AccountInterventionState currentAccountInterventionState) {
        // If no intervention flags are set then there can't have been an intervention
        if (hasNoInterventionFlag(initialAccountInterventionState)
                && hasNoInterventionFlag(currentAccountInterventionState)) {
            return false;
        }

        // If the user is currently reproving their identity then the suspended and reprove identity
        // flags may not have been reset yet.
        if (notBlockedAndNotPasswordReset(
                        initialAccountInterventionState, currentAccountInterventionState)
                && initialAccountInterventionState.isSuspended()
                && currentAccountInterventionState.isSuspended()
                && initialAccountInterventionState.isReproveIdentity()
                && currentAccountInterventionState.isReproveIdentity()) {
            return false;
        }

        // If the user is currently reproving their identity and it has been detected
        if (notBlockedAndNotPasswordReset(
                        initialAccountInterventionState, currentAccountInterventionState)
                && initialAccountInterventionState.isSuspended()
                && !currentAccountInterventionState.isSuspended()
                && initialAccountInterventionState.isReproveIdentity()
                && !currentAccountInterventionState.isReproveIdentity()) {
            return false;
        }

        // Otherwise an intervention flag has been set for some other reason
        try {
            LOGGER.info(
                    LogHelper.buildLogMessage(
                            "Mid journey intervention detected. Initial state: %s Final state: %s"
                                    .formatted(
                                            OBJECT_MAPPER.writeValueAsString(
                                                    initialAccountInterventionState),
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

    private static boolean notBlockedAndNotPasswordReset(
            AccountInterventionState initialAccountInterventionState,
            AccountInterventionState currentAccountInterventionState) {
        return !initialAccountInterventionState.isBlocked()
                && !initialAccountInterventionState.isResetPassword()
                && !currentAccountInterventionState.isBlocked()
                && !currentAccountInterventionState.isResetPassword();
    }

    private static boolean hasNoInterventionFlag(
            AccountInterventionState accountInterventionState) {
        return !accountInterventionState.isResetPassword()
                && !accountInterventionState.isBlocked()
                && !accountInterventionState.isReproveIdentity()
                && !accountInterventionState.isSuspended();
    }
}
