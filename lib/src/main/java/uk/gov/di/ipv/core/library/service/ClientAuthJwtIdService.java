package uk.gov.di.ipv.core.library.service;

import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.persistence.DataStore;
import uk.gov.di.ipv.core.library.persistence.item.ClientAuthJwtIdItem;

import java.time.Instant;

import static uk.gov.di.ipv.core.library.config.EnvironmentVariable.CLIENT_AUTH_JWT_IDS_TABLE_NAME;

public class ClientAuthJwtIdService {
    private final DataStore<ClientAuthJwtIdItem> dataStore;
    private final ConfigurationService configurationService;

    @ExcludeFromGeneratedCoverageReport
    public ClientAuthJwtIdService(ConfigurationService configurationService) {
        this.configurationService = configurationService;
        boolean isRunningLocally = this.configurationService.isRunningLocally();
        this.dataStore =
                new DataStore<>(
                        this.configurationService.getEnvironmentVariable(
                                CLIENT_AUTH_JWT_IDS_TABLE_NAME),
                        ClientAuthJwtIdItem.class,
                        DataStore.getClient(isRunningLocally),
                        isRunningLocally,
                        configurationService);
    }

    // For tests
    public ClientAuthJwtIdService(
            ConfigurationService configurationService, DataStore<ClientAuthJwtIdItem> dataStore) {
        this.configurationService = configurationService;
        this.dataStore = dataStore;
    }

    public ClientAuthJwtIdItem getClientAuthJwtIdItem(String jwtId) {
        return dataStore.getItem(jwtId, false);
    }

    public void persistClientAuthJwtId(String jwtId) {
        String timestamp = Instant.now().toString();
        ClientAuthJwtIdItem clientAuthJwtIdItem = new ClientAuthJwtIdItem(jwtId, timestamp);
        dataStore.create(clientAuthJwtIdItem);
    }
}
