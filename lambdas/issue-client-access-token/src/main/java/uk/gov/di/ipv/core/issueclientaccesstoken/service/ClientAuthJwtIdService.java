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

    // For tests
    public ClientAuthJwtIdService(DataStore<ClientAuthJwtIdItem> dataStore) {
        this.dataStore = dataStore;
    }

    @ExcludeFromGeneratedCoverageReport
    public ClientAuthJwtIdService(ConfigService configService) {
        this.dataStore =
                DataStore.create(
                        CLIENT_AUTH_JWT_IDS_TABLE_NAME, ClientAuthJwtIdItem.class, configService);
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
