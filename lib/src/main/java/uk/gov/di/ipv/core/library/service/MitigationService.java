package uk.gov.di.ipv.core.library.service;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.persistence.DataStore;
import uk.gov.di.ipv.core.library.persistence.item.MitigationItem;

import java.util.List;

import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.CRI_RESPONSE_TTL;
import static uk.gov.di.ipv.core.library.config.EnvironmentVariable.MITIGATIONS_TABLE_NAME;

public class MitigationService {
    private static final Logger LOGGER = LogManager.getLogger();

    private final DataStore<MitigationItem> dataStore;
    private final ConfigService configService;

    @ExcludeFromGeneratedCoverageReport
    public MitigationService(ConfigService configService) {
        this.configService = configService;
        boolean isRunningLocally = this.configService.isRunningLocally();
        dataStore =
                new DataStore<>(
                        this.configService.getEnvironmentVariable(MITIGATIONS_TABLE_NAME),
                        MitigationItem.class,
                        DataStore.getClient(isRunningLocally),
                        isRunningLocally,
                        configService);
    }

    public MitigationService(DataStore<MitigationItem> dataStore, ConfigService configService) {
        this.dataStore = dataStore;
        this.configService = configService;
    }

    public MitigationItem getIpvSession(String ipvSessionId) {
        return dataStore.getItem(ipvSessionId);
    }

    public List<MitigationItem> getInFlightMitigations(String userId) {
        return dataStore.getItems(userId);
    }

    public void addInFlightMitigation(String userId, String contraIndicatorCode) {
        dataStore.create(
                MitigationItem.builder()
                        .userId(userId)
                        .contraIndicatorCode(contraIndicatorCode)
                        .build(),
                CRI_RESPONSE_TTL);
    }

    public void deleteInFlightMitigation(String userId, String contraIndicatorCode) {
        dataStore.delete(userId, contraIndicatorCode);
    }

    public void deleteInFlightMitigations(String userId) {
        dataStore.delete(userId);
    }

    public void updateIpvSession(MitigationItem updatedMitigationItem) {
        dataStore.update(updatedMitigationItem);
    }
}
