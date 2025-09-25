package uk.gov.di.ipv.core.library.ais.service;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.ipv.core.library.ais.client.AisClient;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.domain.AisInterventionType;
import uk.gov.di.ipv.core.library.service.ConfigService;

import static uk.gov.di.ipv.core.library.domain.AisInterventionType.AIS_NO_INTERVENTION;

public class AisService {
    private static final Logger LOGGER = LogManager.getLogger();
    private final AisClient aisClient;
    private static final String AIS_FAIL_OPEN_ERROR_DESCRIPTION =
            "Exception while fetching account intervention status. Assuming no intervention.";

    @ExcludeFromGeneratedCoverageReport
    public AisService(ConfigService configService) {
        this.aisClient = new AisClient(configService);
    }

    @ExcludeFromGeneratedCoverageReport
    public AisService(AisClient aisClient) {
        this.aisClient = aisClient;
    }

    public AisInterventionType fetchAisInterventionType(String userId) {
        try {
            var interventionDetails = aisClient.getAccountInterventionStatus(userId);
            return interventionDetails.getIntervention().getDescription();
        } catch (Exception e) {
            LOGGER.error(AIS_FAIL_OPEN_ERROR_DESCRIPTION, e);
            return AIS_NO_INTERVENTION;
        }
    }
}
