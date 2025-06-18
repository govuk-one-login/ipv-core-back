package uk.gov.di.ipv.core.library.ais.service;

import uk.gov.di.ipv.core.library.ais.client.AisClient;
import uk.gov.di.ipv.core.library.ais.enums.AisInterventionType;
import uk.gov.di.ipv.core.library.ais.exception.AisClientException;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.dto.AccountInterventionState;
import uk.gov.di.ipv.core.library.service.ConfigService;

public class AisService {
    private final AisClient aisClient;

    @ExcludeFromGeneratedCoverageReport
    public AisService(ConfigService configService) {
        this.aisClient = new AisClient(configService);
    }

    @ExcludeFromGeneratedCoverageReport
    public AisService(AisClient aisClient) {
        this.aisClient = aisClient;
    }

    public AccountInterventionState fetchAccountState(String userId) throws AisClientException {
        var interventionDetails = aisClient.getAccountInterventionStatus(userId);
        return interventionDetails.getState();
    }

    @ExcludeFromGeneratedCoverageReport
    public AccountInterventionState getStateByIntervention(AisInterventionType interventionType) {
        switch (interventionType) {
            case AIS_NO_INTERVENTION, AIS_ACCOUNT_UNSUSPENDED, AIS_ACCOUNT_UNBLOCKED -> {
                return new AccountInterventionState(false, false, false, false);
            }
            case AIS_ACCOUNT_SUSPENDED -> {
                return new AccountInterventionState(false, true, false, false);
            }
            case AIS_ACCOUNT_BLOCKED -> {
                return new AccountInterventionState(true, false, false, false);
            }
            case AIS_FORCED_USER_PASSWORD_RESET -> {
                return new AccountInterventionState(false, true, false, true);
            }
            case AIS_FORCED_USER_IDENTITY_VERIFY -> {
                return new AccountInterventionState(false, true, true, false);
            }
            case AIS_FORCED_USER_PASSWORD_RESET_AND_IDENTITY_VERIFY -> {
                return new AccountInterventionState(false, true, true, true);
            }
            default -> {
                return new AccountInterventionState(false, false, false, false);
            }
        }
    }
}
