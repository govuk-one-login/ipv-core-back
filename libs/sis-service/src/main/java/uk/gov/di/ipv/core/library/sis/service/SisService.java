package uk.gov.di.ipv.core.library.sis.service;

import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.sis.client.SisClient;
import uk.gov.di.ipv.core.library.sis.client.SisGetStoredIdentityResult;

public class SisService {
    private final SisClient sisClient;

    @ExcludeFromGeneratedCoverageReport
    public SisService(SisClient sisClient) {
        this.sisClient = sisClient;
    }

    @ExcludeFromGeneratedCoverageReport
    public SisService(ConfigService configService) {
        this.sisClient = new SisClient(configService);
    }

    public SisGetStoredIdentityResult getStoredIdentity(
            ClientOAuthSessionItem clientOAuthSessionItem) {
        return sisClient.getStoredIdentity(
                clientOAuthSessionItem.getEvcsAccessToken(),
                clientOAuthSessionItem.getVtrAsVots(),
                clientOAuthSessionItem.getGovukSigninJourneyId());
    }
}
