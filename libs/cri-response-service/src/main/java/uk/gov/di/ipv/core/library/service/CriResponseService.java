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
    private final DataStore<CriResponseItem> dataStore;

    @ExcludeFromGeneratedCoverageReport
    public CriResponseService(ConfigService configService) {
        this.dataStore =
                new DataStore<>(
                        configService.getEnvironmentVariable(CRI_RESPONSE_TABLE_NAME),
                        CriResponseItem.class,
                        DataStore.getClient(),
                        configService);
    }

    public CriResponseService(DataStore<CriResponseItem> dataStore) {
        this.dataStore = dataStore;
    }

    public CriResponseItem getCriResponseItem(String userId, String criId) {
        return dataStore.getItem(userId, criId);
    }

    public void persistCriResponse(
            String userId,
            String credentialIssuer,
            String issuerResponse,
            String oauthState,
            String status,
            List<String> featureSet) {
        CriResponseItem criResponseItem =
                CriResponseItem.builder()
                        .userId(userId)
                        .credentialIssuer(credentialIssuer)
                        .issuerResponse(issuerResponse)
                        .oauthState(oauthState)
                        .dateCreated(Instant.now())
                        .status(status)
                        .featureSet(featureSet)
                        .build();
        dataStore.create(criResponseItem, ConfigurationVariable.CRI_RESPONSE_TTL);
    }

    public CriResponseItem getFaceToFaceRequest(String userId) {
        return dataStore.getItem(userId, "f2f");
    }

    public void deleteCriResponseItem(String userId, String credentialIssuer) {
        dataStore.delete(userId, credentialIssuer);
    }

    public void updateCriResponseItem(CriResponseItem responseItem) {
        dataStore.update(responseItem);
    }
}
