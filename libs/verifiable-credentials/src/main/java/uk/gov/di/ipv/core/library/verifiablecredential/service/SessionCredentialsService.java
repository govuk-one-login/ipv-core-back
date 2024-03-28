package uk.gov.di.ipv.core.library.verifiablecredential.service;

import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
import uk.gov.di.ipv.core.library.config.EnvironmentVariable;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.exceptions.VerifiableCredentialException;
import uk.gov.di.ipv.core.library.persistence.DataStore;
import uk.gov.di.ipv.core.library.persistence.item.SessionCredentialItem;
import uk.gov.di.ipv.core.library.service.ConfigService;

public class SessionCredentialsService {
    private static final Logger LOGGER = LogManager.getLogger();
    private final DataStore<SessionCredentialItem> dataStore;

    public SessionCredentialsService(DataStore<SessionCredentialItem> dataStore) {
        this.dataStore = dataStore;
    }

    @ExcludeFromGeneratedCoverageReport
    public SessionCredentialsService(ConfigService configService) {
        this.dataStore =
                new DataStore<>(
                        configService.getEnvironmentVariable(
                                EnvironmentVariable.SESSION_CREDENTIALS_TABLE_NAME),
                        SessionCredentialItem.class,
                        DataStore.getClient(),
                        configService);
    }

    public void persistCredential(
            VerifiableCredential credential, String ipvSessionId, boolean receivedThisSession)
            throws VerifiableCredentialException {
        try {
            dataStore.create(
                    credential.toSessionCredentialItem(ipvSessionId, receivedThisSession),
                    ConfigurationVariable.SESSION_CREDENTIALS_TTL);
        } catch (Exception e) {
            LOGGER.error("Error persisting session credential: {}", e.getMessage(), e);
            throw new VerifiableCredentialException(
                    HTTPResponse.SC_SERVER_ERROR, ErrorResponse.FAILED_TO_SAVE_CREDENTIAL);
        }
    }
}
