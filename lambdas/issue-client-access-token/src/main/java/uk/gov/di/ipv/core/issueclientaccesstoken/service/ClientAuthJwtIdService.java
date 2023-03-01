package uk.gov.di.ipv.core.issueclientaccesstoken.service;

import uk.gov.di.ipv.core.issueclientaccesstoken.persistance.item.ClientAuthJwtIdItem;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.persistence.DataStore;
import uk.gov.di.ipv.core.library.service.ConfigService;

import java.time.Instant;

import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.BACKEND_SESSION_TTL;
import static uk.gov.di.ipv.core.library.config.EnvironmentVariable.CLIENT_AUTH_JWT_IDS_TABLE_NAME;

public class ClientAuthJwtIdService {
    private final DataStore<ClientAuthJwtIdItem> dataStore;
    private final ConfigService configService;

    @ExcludeFromGeneratedCoverageReport
    public ClientAuthJwtIdService(ConfigService configService) {
        this.configService = configService;
        boolean isRunningLocally = this.configService.isRunningLocally();
        this.dataStore =
                new DataStore<>(
                        this.configService.getEnvironmentVariable(CLIENT_AUTH_JWT_IDS_TABLE_NAME),
                        ClientAuthJwtIdItem.class,
                        DataStore.getClient(isRunningLocally),
                        isRunningLocally,
                        configService);
    }

    // For tests
    public ClientAuthJwtIdService(
            ConfigService configService, DataStore<ClientAuthJwtIdItem> dataStore) {
        this.configService = configService;
        this.dataStore = dataStore;
    }

    public ClientAuthJwtIdItem getClientAuthJwtIdItem(String jwtId) {
        return dataStore.getItem(jwtId, false);
    }

    public void persistClientAuthJwtId(String jwtId) {
        String timestamp = Instant.now().toString();
        ClientAuthJwtIdItem clientAuthJwtIdItem = new ClientAuthJwtIdItem(jwtId, timestamp);
        dataStore.create(clientAuthJwtIdItem, BACKEND_SESSION_TTL);
    }
}
