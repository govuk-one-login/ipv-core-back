package uk.gov.di.ipv.core.library.sis.service;

import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.sis.client.SisClient;
import uk.gov.di.ipv.core.library.sis.client.SisGetStoredIdentityResult;
import uk.gov.di.ipv.core.library.service.ConfigService;

public class SisService {
    private final SisClient sisClient;
    private final ConfigService configService;

    @ExcludeFromGeneratedCoverageReport
    public SisService(
            SisClient sisClient,
            ConfigService configService) {
        this.sisClient = sisClient;
        this.configService = configService;
    }

    @ExcludeFromGeneratedCoverageReport
    public SisService(ConfigService configService) {
        this.sisClient = new SisClient(configService);
        this.configService = configService;
    }

    public SisGetStoredIdentityResult getStoredIdentity(String evcsAccessToken) {
        return sisClient.getStoredIdentity(evcsAccessToken);
    }
}
