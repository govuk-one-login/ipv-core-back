package uk.gov.di.ipv.core.library.service;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.domain.IpvJourneyTypes;
import uk.gov.di.ipv.core.library.persistence.DataStore;
import uk.gov.di.ipv.core.library.persistence.item.CriOAuthSessionItem;

import java.time.Instant;

import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.BACKEND_SESSION_TTL;
import static uk.gov.di.ipv.core.library.config.EnvironmentVariable.CRI_OAUTH_SESSIONS_TABLE_NAME;

public class CriOAuthSessionService {
    private static final Logger LOGGER = LogManager.getLogger();

    private final DataStore<CriOAuthSessionItem> dataStore;
    private final ConfigService configService;

    @ExcludeFromGeneratedCoverageReport
    public CriOAuthSessionService(ConfigService configService) {
        this.configService = configService;
        boolean isRunningLocally = this.configService.isRunningLocally();
        dataStore =
                new DataStore<>(
                        this.configService.getEnvironmentVariable(CRI_OAUTH_SESSIONS_TABLE_NAME),
                        CriOAuthSessionItem.class,
                        DataStore.getClient(isRunningLocally),
                        isRunningLocally,
                        configService);
    }

    public CriOAuthSessionService(
            DataStore<CriOAuthSessionItem> dataStore, ConfigService configService) {
        this.dataStore = dataStore;
        this.configService = configService;
    }

    public CriOAuthSessionItem getCriOauthSessionItem(String criOAuthSessionId) {
        return dataStore.getItem(criOAuthSessionId);
    }

    public CriOAuthSessionItem persistCriOAuthSession(
            String state, String criId, String userId, String govukSigninJourneyId) {

        CriOAuthSessionItem criOAuthSessionItem =
                CriOAuthSessionItem.builder()
                        .criOAuthSessionId(state)
                        .criId(criId)
                        .userId(userId)
                        .govukSigninJourneyId(govukSigninJourneyId)
                        .creationDateTime(Instant.now().toString())
                        .journeyType(IpvJourneyTypes.IPV_CORE_MAIN_JOURNEY)
                        .build();

        dataStore.create(criOAuthSessionItem, BACKEND_SESSION_TTL);
        LOGGER.info(
                "Cri OAuth Session Item {} created. ", criOAuthSessionItem.getCriOAuthSessionId());

        return criOAuthSessionItem;
    }

    public void updateCriOAuthSessionItem(CriOAuthSessionItem updatedCriOAuthSessionItem) {
        dataStore.update(updatedCriOAuthSessionItem);
        LOGGER.info(
                "Cri OAuth Session Item {} updated. ",
                updatedCriOAuthSessionItem.getCriOAuthSessionId());
    }
}
