package uk.gov.di.ipv.service;

import uk.gov.di.ipv.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.persistence.DataStore;
import uk.gov.di.ipv.persistence.item.IpvSessionItem;

import java.time.Instant;
import java.util.UUID;

public class IpvSessionService {

    private final DataStore<IpvSessionItem> dataStore;
    private final ConfigurationService configurationService;

    @ExcludeFromGeneratedCoverageReport
    public IpvSessionService() {
        this.configurationService = new ConfigurationService();
        dataStore =
                new DataStore<>(
                        configurationService.getIpvSessionTableName(),
                        IpvSessionItem.class,
                        DataStore.getClient());
    }

    public IpvSessionService(
            DataStore<IpvSessionItem> dataStore, ConfigurationService configurationService) {
        this.dataStore = dataStore;
        this.configurationService = configurationService;
    }

    public String generateIpvSession() {
        IpvSessionItem ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setIpvSessionId(UUID.randomUUID().toString());
        ipvSessionItem.setCreationDateTime(Instant.now().toString());
        dataStore.create(ipvSessionItem);

        return ipvSessionItem.getIpvSessionId();
    }
}
