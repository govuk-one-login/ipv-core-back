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
        if (!initialAccountInterventionState.isBlocked()
                && !initialAccountInterventionState.isSuspended()
                && !initialAccountInterventionState.isResetPassword()
                && !initialAccountInterventionState.isReproveIdentity()) {
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
}
