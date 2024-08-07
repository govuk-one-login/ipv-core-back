package uk.gov.di.ipv.core.library.service;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.message.StringMapMessage;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.domain.Cri;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.persistence.DataStore;
import uk.gov.di.ipv.core.library.persistence.item.CriOAuthSessionItem;

import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.BACKEND_SESSION_TTL;
import static uk.gov.di.ipv.core.library.config.EnvironmentVariable.CRI_OAUTH_SESSIONS_TABLE_NAME;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_CRI_OAUTH_SESSION_ID;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_MESSAGE_DESCRIPTION;

public class CriOAuthSessionService {
    private static final Logger LOGGER = LogManager.getLogger();

    private final DataStore<CriOAuthSessionItem> dataStore;

    public CriOAuthSessionService(DataStore<CriOAuthSessionItem> dataStore) {
        this.dataStore = dataStore;
    }

    @ExcludeFromGeneratedCoverageReport
    public CriOAuthSessionService(ConfigService configService) {
        dataStore =
                DataStore.create(
                        CRI_OAUTH_SESSIONS_TABLE_NAME, CriOAuthSessionItem.class, configService);
    }

    public CriOAuthSessionItem getCriOauthSessionItem(String criOAuthSessionId) {
        var criOauthSessionItem = dataStore.getItem(criOAuthSessionId);
        if (criOauthSessionItem == null) {
            LOGGER.warn(LogHelper.buildLogMessage("CRI OAuth session not found"));
        }
        return criOauthSessionItem;
    }

    public CriOAuthSessionItem persistCriOAuthSession(
            String state, Cri cri, String clientOAuthSessionId, String connection) {

        CriOAuthSessionItem criOAuthSessionItem =
                CriOAuthSessionItem.builder()
                        .criOAuthSessionId(state)
                        .criId(cri.getId())
                        .clientOAuthSessionId(clientOAuthSessionId)
                        .connection(connection)
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
}
