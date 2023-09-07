package uk.gov.di.ipv.core.library.service;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.message.StringMapMessage;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.persistence.DataStore;
import uk.gov.di.ipv.core.library.persistence.item.CriOAuthSessionItem;

import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.BACKEND_SESSION_TTL;
import static uk.gov.di.ipv.core.library.config.EnvironmentVariable.CRI_OAUTH_SESSIONS_TABLE_NAME;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_CRI_OAUTH_SESSION_ID;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_MESSAGE_DESCRIPTION;

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
            String state, String criId, String clientOAuthSessionId) {

        CriOAuthSessionItem criOAuthSessionItem =
                CriOAuthSessionItem.builder()
                        .criOAuthSessionId(state)
                        .criId(criId)
                        .clientOAuthSessionId(clientOAuthSessionId)
                        .build();

        dataStore.create(criOAuthSessionItem, BACKEND_SESSION_TTL);
        LOGGER.info(
                new StringMapMessage()
                        .with(
                                LOG_MESSAGE_DESCRIPTION.getFieldName(),
                                "Cri OAuth Session item created.")
                        .with(
                                LOG_CRI_OAUTH_SESSION_ID.getFieldName(),
                                criOAuthSessionItem.getCriOAuthSessionId()));
        return criOAuthSessionItem;
    }

    public void updateCriOAuthSessionItem(CriOAuthSessionItem updatedCriOAuthSessionItem) {
        dataStore.update(updatedCriOAuthSessionItem);
        LOGGER.info(
                new StringMapMessage()
                        .with(
                                LOG_MESSAGE_DESCRIPTION.getFieldName(),
                                "Cri OAuth Session item updated.")
                        .with(
                                LOG_CRI_OAUTH_SESSION_ID.getFieldName(),
                                updatedCriOAuthSessionItem.getCriOAuthSessionId()));
    }
}
