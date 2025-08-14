package uk.gov.di.ipv.core.library.ais.service;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.ipv.core.library.ais.client.AisClient;
import uk.gov.di.ipv.core.library.ais.enums.AisInterventionType;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.dto.AccountInterventionState;
import uk.gov.di.ipv.core.library.service.ConfigService;

public class AisService {
    private static final Logger LOGGER = LogManager.getLogger();
    private final AisClient aisClient;

    @ExcludeFromGeneratedCoverageReport
    public AisService(ConfigService configService) {
        this.aisClient = new AisClient(configService);
    }

    @ExcludeFromGeneratedCoverageReport
    public AisService(AisClient aisClient) {
        this.aisClient = aisClient;
    }

    public AccountInterventionState fetchAccountState(String userId) {
        try {
            var interventionDetails = aisClient.getAccountInterventionStatus(userId);
            return interventionDetails.getState();
        } catch (Exception e) {
            LOGGER.error(
                    "Exception while fetching account intervention status. Assuming no intervention.",
                    e);
            return getStateByIntervention(AisInterventionType.AIS_NO_INTERVENTION);
        }
    }

    @ExcludeFromGeneratedCoverageReport
    public AccountInterventionState getStateByIntervention(AisInterventionType interventionType) {
        return switch (interventionType) {
            case AIS_ACCOUNT_SUSPENDED ->
                    AccountInterventionState.builder()
                            .isBlocked(false)
                            .isSuspended(true)
                            .isReproveIdentity(false)
                            .isResetPassword(false)
                            .build();
            case AIS_ACCOUNT_BLOCKED ->
                    AccountInterventionState.builder()
                            .isBlocked(true)
                            .isSuspended(false)
                            .isReproveIdentity(false)
                            .isResetPassword(false)
                            .build();
            case AIS_FORCED_USER_PASSWORD_RESET ->
                    AccountInterventionState.builder()
                            .isBlocked(false)
                            .isSuspended(true)
                            .isReproveIdentity(false)
                            .isResetPassword(true)
                            .build();
            case AIS_FORCED_USER_IDENTITY_VERIFY ->
                    AccountInterventionState.builder()
                            .isBlocked(false)
                            .isSuspended(true)
                            .isReproveIdentity(true)
                            .isResetPassword(false)
                            .build();
            case AIS_FORCED_USER_PASSWORD_RESET_AND_IDENTITY_VERIFY ->
                    AccountInterventionState.builder()
                            .isBlocked(false)
                            .isSuspended(true)
                            .isReproveIdentity(true)
                            .isResetPassword(true)
                            .build();
            default ->
                    AccountInterventionState.builder()
                            .isBlocked(false)
                            .isSuspended(false)
                            .isReproveIdentity(false)
                            .isResetPassword(false)
                            .build();
        };
    }
}
