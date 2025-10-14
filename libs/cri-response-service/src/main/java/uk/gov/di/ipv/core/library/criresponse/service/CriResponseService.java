package uk.gov.di.ipv.core.library.criresponse.service;

import com.nimbusds.jwt.util.DateUtils;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.criresponse.domain.AsyncCriStatus;
import uk.gov.di.ipv.core.library.domain.Cri;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.persistence.DataStore;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.CriResponseItem;
import uk.gov.di.ipv.core.library.service.ConfigService;

import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

import static uk.gov.di.ipv.core.library.config.EnvironmentVariable.CRI_RESPONSE_TABLE_NAME;
import static uk.gov.di.ipv.core.library.domain.Cri.DCMAW_ASYNC;
import static uk.gov.di.ipv.core.library.domain.Cri.F2F;

public class CriResponseService {

    public static final String STATUS_PENDING = "pending";
    public static final String STATUS_ERROR = "error";
    public static final String STATUS_ABANDON = "abandon";
    public static final String ERROR_ACCESS_DENIED = "access_denied";
    private final ConfigService configService;
    private final DataStore<CriResponseItem> dataStore;

    @ExcludeFromGeneratedCoverageReport
    public CriResponseService(ConfigService configService) {
        this.dataStore =
                DataStore.create(CRI_RESPONSE_TABLE_NAME, CriResponseItem.class, configService);
        this.configService = configService;
    }

    public CriResponseService(DataStore<CriResponseItem> dataStore, ConfigService configService) {
        this.dataStore = dataStore;
        this.configService = configService;
    }

    public Optional<CriResponseItem> getCriResponseItemWithState(String userId, String state) {
        final List<CriResponseItem> criResponseItems = dataStore.getItems(userId);
        return criResponseItems.stream()
                .filter(item -> Objects.equals(item.getOauthState(), state))
                .findFirst();
    }

    public List<CriResponseItem> getCriResponseItems(String userId) {
        var criResponseItems = dataStore.getItems(userId);
        if (criResponseItems == null) {
            return List.of();
        }
        return criResponseItems;
    }

    public CriResponseItem getCriResponseItem(String userId, Cri cri) {
        return dataStore.getItem(userId, cri.getId());
    }

    public void persistCriResponse(
            ClientOAuthSessionItem clientOAuthSessionItem,
            Cri credentialIssuer,
            String issuerResponse,
            String oauthState,
            String status,
            List<String> featureSet) {
        CriResponseItem criResponseItem =
                CriResponseItem.builder()
                        .userId(clientOAuthSessionItem.getUserId())
                        .credentialIssuer(credentialIssuer.getId())
                        .issuerResponse(issuerResponse)
                        .oauthState(oauthState)
                        .dateCreated(Instant.now())
                        .status(status)
                        .featureSet(featureSet)
                        .reproveIdentity(
                                Boolean.TRUE.equals(clientOAuthSessionItem.getReproveIdentity()))
                        .build();
        dataStore.create(criResponseItem, configService.getCriResponseTtl());
    }

    public void deleteCriResponseItem(String userId, Cri credentialIssuer) {
        dataStore.delete(userId, credentialIssuer.getId());
    }

    public void updateCriResponseItem(CriResponseItem responseItem) {
        dataStore.update(responseItem);
    }

    public AsyncCriStatus getAsyncResponseStatus(
            String userId, List<VerifiableCredential> credentials, boolean isPendingReturn) {
        // F2F CRI response item blocks other async CRI routes, except for
        // enhanced-verification-f2f-fail, which enforces the user stays on the same mitigation
        // route, so it is fine here as we check F2F first.
        var f2fCriResponseItem = getCriResponseItem(userId, F2F);
        if (f2fCriResponseItem != null) {
            var f2fVc = credentials.stream().filter(vc -> vc.getCri().equals(F2F)).findFirst();
            var hasVc = f2fVc.isPresent();

            return new AsyncCriStatus(
                    F2F,
                    f2fCriResponseItem.getStatus(),
                    !hasVc,
                    isPendingReturn,
                    f2fCriResponseItem.isReproveIdentity());
        }

        // DCMAW async VC existence determines success or abandonment
        var dcmawAsyncVc =
                credentials.stream().filter(vc -> vc.getCri().equals(DCMAW_ASYNC)).findFirst();
        if (dcmawAsyncVc.isPresent()) {
            var issuedAt = dcmawAsyncVc.get().getClaimsSet().getIssueTime();
            if (issuedAt != null) {
                var now = DateUtils.toSecondsSinceEpoch(new Date());
                var expiry =
                        DateUtils.toSecondsSinceEpoch(issuedAt)
                                + configService.getDcmawAsyncVcPendingReturnTtl();
                if (now < expiry) {
                    var criResponse = getCriResponseItem(userId, DCMAW_ASYNC);
                    return new AsyncCriStatus(
                            DCMAW_ASYNC,
                            null,
                            false,
                            isPendingReturn,
                            // This shouldn't happen in prod, but default to false is there is no
                            // cri response.
                            // This allows us to test journeys with pre-existing DCMAW Async VCs
                            // without having to go through
                            // the whole journey to populate the datastore.
                            criResponse != null && criResponse.isReproveIdentity());
                }
            }
        }

        return new AsyncCriStatus(null, null, false, false, false);
    }
}
