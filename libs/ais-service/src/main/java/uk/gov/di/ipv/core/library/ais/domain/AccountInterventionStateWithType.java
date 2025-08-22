package uk.gov.di.ipv.core.library.ais.domain;

import uk.gov.di.ipv.core.library.ais.enums.AisInterventionType;
import uk.gov.di.ipv.core.library.dto.AccountInterventionState;

public record AccountInterventionStateWithType(
        AccountInterventionState accountInterventionState,
        AisInterventionType aisInterventionType) {

    public static AccountInterventionStateWithType createDefault() {
        return new AccountInterventionStateWithType(
                AccountInterventionState.builder()
                        .isBlocked(false)
                        .isSuspended(false)
                        .isReproveIdentity(false)
                        .isResetPassword(false)
                        .build(),
                AisInterventionType.AIS_NO_INTERVENTION);
    }
}
