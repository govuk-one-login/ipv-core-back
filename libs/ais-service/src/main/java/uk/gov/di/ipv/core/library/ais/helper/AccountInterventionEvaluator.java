package uk.gov.di.ipv.core.library.ais.helper;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.ipv.core.library.domain.AisInterventionType;
import uk.gov.di.ipv.core.library.dto.AccountInterventionState;
import uk.gov.di.ipv.core.library.helpers.LogHelper;

import static uk.gov.di.ipv.core.library.domain.AisInterventionType.*;
import static uk.gov.di.ipv.core.library.domain.AisInterventionType.AIS_FORCED_USER_IDENTITY_VERIFY;

public final class AccountInterventionEvaluator {

    private static final Logger LOGGER = LogManager.getLogger();
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

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

        boolean bothValid = isValidIntervention(initial) && isValidIntervention(current);
        boolean bothReprove = isBothIdentityVerify(initial, current);
        boolean reproveToValid = isIdentityVerifyToValid(initial, current);

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

    public static boolean isMidOfJourneyInterventionDetected(
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
