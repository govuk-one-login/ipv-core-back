package uk.gov.di.ipv.core.library.ais.helper;

import uk.gov.di.ipv.core.library.dto.AccountInterventionState;

public class AccountInterventionEvaluator {

    private AccountInterventionEvaluator() {
        // prevent initialisation
    }

    public static boolean shouldInvalidateSession(AccountInterventionState interventionState) {
        // if no flags are set then there is no intervention
        if (!interventionState.isBlocked()
                && !interventionState.isSuspended()
                && !interventionState.isResetPassword()
                && !interventionState.isReproveIdentity()) {
            return false;
        }

        // we allow user to proceed to reverify journey
        if (!interventionState.isBlocked()
                && !interventionState.isResetPassword()
                && interventionState.isSuspended()
                && interventionState.isReproveIdentity()) {
            return false;
        }

        return interventionState.isBlocked()
                || interventionState.isResetPassword()
                || interventionState.isSuspended();
    }
}
