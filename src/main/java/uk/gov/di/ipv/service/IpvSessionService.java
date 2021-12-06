package uk.gov.di.ipv.service;

import uk.gov.di.ipv.persistence.DataStore;
import uk.gov.di.ipv.persistence.item.IpvSessionItem;

import java.time.Instant;
import java.util.UUID;

public class IpvSessionService {

    private final DataStore<IpvSessionItem> dataStore;
    private final ConfigurationService configurationService;

    public IpvSessionService() {
        this.configurationService = ConfigurationService.getInstance();
        dataStore = new DataStore<>(configurationService.getIpvSessionTableName(), IpvSessionItem.class);
    }

    public IpvSessionService(DataStore<IpvSessionItem> dataStore, ConfigurationService configurationService) {
        this.dataStore = dataStore;
        this.configurationService = configurationService;
    }

    public IpvSessionItem generateIpvSession() {
        IpvSessionItem ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setIpvSessionId(UUID.randomUUID().toString());
        ipvSessionItem.setCreationDateTime(Instant.now().toString());
        dataStore.create(ipvSessionItem);

        return ipvSessionItem;
    }
}
