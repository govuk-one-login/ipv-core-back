package uk.gov.di.ipv.core.library.ais.service;

import uk.gov.di.ipv.core.library.ais.client.AisClient;
import uk.gov.di.ipv.core.library.ais.exception.AisClientException;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
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

    public boolean needsToReproveIdentity(String userId) throws AisClientException {
        var interventionDetails = aisClient.getAccountInterventionStatus(userId);
        return interventionDetails.getState().isReproveIdentity();
    }
}
