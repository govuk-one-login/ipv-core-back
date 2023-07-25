package uk.gov.di.ipv.core.library.service;

import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
import uk.gov.di.ipv.core.library.persistence.DataStore;
import uk.gov.di.ipv.core.library.persistence.item.CriResponseItem;

import java.time.Instant;
import java.util.List;

import static uk.gov.di.ipv.core.library.config.EnvironmentVariable.CRI_RESPONSE_TABLE_NAME;

public class CriResponseService {

    public static final String STATUS_PENDING = "pending";
    public static final String STATUS_ERROR = "error";
    private final ConfigService configService;
    private final DataStore<CriResponseItem> dataStore;

    @ExcludeFromGeneratedCoverageReport
    public CriResponseService(ConfigService configService) {
        this.configService = configService;
        boolean isRunningLocally = this.configService.isRunningLocally();
        this.dataStore =
                new DataStore<>(
                        this.configService.getEnvironmentVariable(CRI_RESPONSE_TABLE_NAME),
                        CriResponseItem.class,
                        DataStore.getClient(isRunningLocally),
                        isRunningLocally,
                        configService);
    }

    public CriResponseService(ConfigService configService, DataStore<CriResponseItem> dataStore) {
        this.configService = configService;
        this.dataStore = dataStore;
    }

    public List<CriResponseItem> getCriResponseItems(String userId) {
        return dataStore.getItems(userId);
    }

    public CriResponseItem getCriResponseItem(String userId, String criId) {
        return dataStore.getItem(userId, criId);
    }

    public void persistCriResponse(
            String userId,
            String credentialIssuer,
            String issuerResponse,
            String oauthState,
            String status) {
        CriResponseItem criResponseItem =
                CriResponseItem.builder()
                        .userId(userId)
                        .credentialIssuer(credentialIssuer)
                        .issuerResponse(issuerResponse)
                        .oauthState(oauthState)
                        .dateCreated(Instant.now())
                        .status(status)
                        .build();
        dataStore.create(criResponseItem, ConfigurationVariable.CRI_RESPONSE_TTL);
    }

    public CriResponseItem userHasFaceToFaceRequest(String userId) {
        CriResponseItem userRequest = dataStore.getItem(userId, "f2f");
        return userRequest;
    }

    public void deleteCriResponseItem(String userId, String credentialIssuer) {
        dataStore.delete(userId, credentialIssuer);
    }

    public void updateCriResponseItem(CriResponseItem responseItem) {
        dataStore.update(responseItem);
    }
}
