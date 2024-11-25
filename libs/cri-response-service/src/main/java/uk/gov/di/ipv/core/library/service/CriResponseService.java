package uk.gov.di.ipv.core.library.service;

import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
import uk.gov.di.ipv.core.library.domain.Cri;
import uk.gov.di.ipv.core.library.persistence.DataStore;
import uk.gov.di.ipv.core.library.persistence.item.CriResponseItem;
import uk.gov.di.ipv.core.library.service.domain.AsyncCriStatus;

import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.function.Function;

import static uk.gov.di.ipv.core.library.config.CoreFeatureFlag.EVCS_READ_ENABLED;
import static uk.gov.di.ipv.core.library.config.EnvironmentVariable.CRI_RESPONSE_TABLE_NAME;
import static uk.gov.di.ipv.core.library.domain.Cri.ASYNC_CRIS;

public class CriResponseService {

    public static final String STATUS_PENDING = "pending";
    public static final String STATUS_ERROR = "error";
    public static final String STATUS_ABANDON = "abandon";
    public static final String ERROR_ACCESS_DENIED = "access_denied";
    private final ConfigService configService;
    private final DataStore<CriResponseItem> dataStore;

    @ExcludeFromGeneratedCoverageReport
    public CriResponseService(ConfigService configService) {
        this.configService = configService;
        this.dataStore =
                DataStore.create(CRI_RESPONSE_TABLE_NAME, CriResponseItem.class, configService);
    }

    public CriResponseService(DataStore<CriResponseItem> dataStore) {
        this.configService = ConfigService.create();
        this.dataStore = dataStore;
    }

    public Optional<CriResponseItem> getCriResponseItemWithState(String userId, String state) {
        final List<CriResponseItem> criResponseItems = dataStore.getItems(userId);
        return criResponseItems.stream()
                .filter(item -> Objects.equals(item.getOauthState(), state))
                .findFirst();
    }

    public CriResponseItem getCriResponseItem(String userId, Cri cri) {
        return dataStore.getItem(userId, cri.getId());
    }

    public void persistCriResponse(
            String userId,
            Cri credentialIssuer,
            String issuerResponse,
            String oauthState,
            String status,
            List<String> featureSet) {
        CriResponseItem criResponseItem =
                CriResponseItem.builder()
                        .userId(userId)
                        .credentialIssuer(credentialIssuer.getId())
                        .issuerResponse(issuerResponse)
                        .oauthState(oauthState)
                        .dateCreated(Instant.now())
                        .status(status)
                        .featureSet(featureSet)
                        .build();
        dataStore.create(criResponseItem, ConfigurationVariable.CRI_RESPONSE_TTL);
    }

    public void deleteCriResponseItem(String userId, Cri credentialIssuer) {
        dataStore.delete(userId, credentialIssuer.getId());
    }

    public void updateCriResponseItem(CriResponseItem responseItem) {
        dataStore.update(responseItem);
    }

    public AsyncCriStatus getAsyncResponseStatus(
            String userId,
            Function<Cri, Boolean> hasVc,
            Function<Cri, Long> getVcIat,
            boolean isPendingEvcsIdentity) {
        final var criResponseItem =
                dataStore.getItems(userId).stream()
                        .filter(item -> ASYNC_CRIS.contains(Cri.fromId(item.getCredentialIssuer())))
                        .findFirst()
                        .orElse(null);
        if (Objects.isNull(criResponseItem)) {
            return new AsyncCriStatus(null, null, null, false, false);
        }

        var cri = Cri.fromId(criResponseItem.getCredentialIssuer());
        final boolean hasNoVc = !hasVc.apply(cri);
        final boolean isComplete =
                hasVc.apply(cri)
                        && (!configService.enabled(EVCS_READ_ENABLED) || isPendingEvcsIdentity);
        final Long iat = getVcIat.apply(cri);

        return new AsyncCriStatus(cri, iat, criResponseItem.getStatus(), hasNoVc, isComplete);
    }
}
