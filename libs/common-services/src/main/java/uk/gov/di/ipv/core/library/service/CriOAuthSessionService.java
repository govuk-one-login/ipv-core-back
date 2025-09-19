package uk.gov.di.ipv.core.library.service;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.message.StringMapMessage;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.domain.Cri;
import uk.gov.di.ipv.core.library.exceptions.CriOAuthSessionNotFoundException;
import uk.gov.di.ipv.core.library.exceptions.NonRetryableException;
import uk.gov.di.ipv.core.library.exceptions.RetryableException;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.persistence.DataStore;
import uk.gov.di.ipv.core.library.persistence.item.CriOAuthSessionItem;
import uk.gov.di.ipv.core.library.retry.Retry;
import uk.gov.di.ipv.core.library.retry.Sleeper;

import static uk.gov.di.ipv.core.library.config.EnvironmentVariable.CRI_OAUTH_SESSIONS_TABLE_NAME;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_CRI_OAUTH_SESSION_ID;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_MESSAGE_DESCRIPTION;

public class CriOAuthSessionService {
    private static final Logger LOGGER = LogManager.getLogger();

    // Max sleeping time will be roughly WAIT_TIME * 2 ^ (MAX_ATTEMPTS - 1), plus execution time
    // AWS say 'Consistency across all copies of data is usually reached within a second'
    private static final int MAX_ATTEMPTS = 5;
    private static final int WAIT_TIME_MILLIS = 50;

    private final DataStore<CriOAuthSessionItem> dataStore;
    private final Sleeper sleeper;
    private ConfigService configService;

    public CriOAuthSessionService(DataStore<CriOAuthSessionItem> dataStore, Sleeper sleeper) {
        this.dataStore = dataStore;
        this.sleeper = sleeper;
    }

    @ExcludeFromGeneratedCoverageReport
    public CriOAuthSessionService(ConfigService configService) {
        this.configService = configService;
        dataStore =
                DataStore.create(
                        CRI_OAUTH_SESSIONS_TABLE_NAME, CriOAuthSessionItem.class, configService);
        sleeper = new Sleeper();
    }

    public CriOAuthSessionItem getCriOauthSessionItem(String criOAuthSessionId) {
        try {
            return Retry.runTaskWithBackoff(
                    sleeper,
                    MAX_ATTEMPTS,
                    WAIT_TIME_MILLIS,
                    () -> {
                        var criOauthSessionItem = dataStore.getItem(criOAuthSessionId);
                        if (criOauthSessionItem == null) {
                            throw new RetryableException(new CriOAuthSessionNotFoundException());
                        }
                        return criOauthSessionItem;
                    });
        } catch (InterruptedException | NonRetryableException e) {
            if (e instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            LOGGER.warn(LogHelper.buildErrorMessage("Could not find CRI OAuth session", e));
            return null;
        }
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

        dataStore.create(criOAuthSessionItem, configService.getBackendSessionTtl());
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
