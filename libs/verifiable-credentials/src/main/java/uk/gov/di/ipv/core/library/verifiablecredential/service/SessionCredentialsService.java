package uk.gov.di.ipv.core.library.verifiablecredential.service;

import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
import uk.gov.di.ipv.core.library.config.EnvironmentVariable;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.exceptions.CredentialParseException;
import uk.gov.di.ipv.core.library.exceptions.VerifiableCredentialException;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.persistence.DataStore;
import uk.gov.di.ipv.core.library.persistence.item.SessionCredentialItem;
import uk.gov.di.ipv.core.library.service.ConfigService;

import java.util.ArrayList;
import java.util.List;

import static uk.gov.di.ipv.core.library.config.CoreFeatureFlag.SESSION_CREDENTIALS_TABLE_WRITES;

public class SessionCredentialsService {
    private static final Logger LOGGER = LogManager.getLogger();
    private final DataStore<SessionCredentialItem> dataStore;
    private final ConfigService configService;

    public SessionCredentialsService(
            DataStore<SessionCredentialItem> dataStore, ConfigService configService) {
        this.dataStore = dataStore;
        this.configService = configService;
    }

    @ExcludeFromGeneratedCoverageReport
    public SessionCredentialsService(ConfigService configService) {
        this.configService = configService;
        this.dataStore =
                new DataStore<>(
                        configService.getEnvironmentVariable(
                                EnvironmentVariable.SESSION_CREDENTIALS_TABLE_NAME),
                        SessionCredentialItem.class,
                        DataStore.getClient(),
                        configService);
    }

    public List<VerifiableCredential> getCredentials(String ipvSessionId, String userId)
            throws VerifiableCredentialException {
        try {
            var verifiableCredentialList = new ArrayList<VerifiableCredential>();
            for (var credential : dataStore.getItems(ipvSessionId)) {
                verifiableCredentialList.add(
                        VerifiableCredential.fromSessionCredentialItem(credential, userId));
            }

            return verifiableCredentialList;
        } catch (CredentialParseException e) {
            LOGGER.error(LogHelper.buildErrorMessage("Error parsing session credential item", e));
            throw new VerifiableCredentialException(
                    HTTPResponse.SC_SERVER_ERROR, ErrorResponse.FAILED_TO_PARSE_ISSUED_CREDENTIALS);
        } catch (Exception e) {
            LOGGER.error(LogHelper.buildErrorMessage("Error getting session credentials", e));
            throw new VerifiableCredentialException(
                    HTTPResponse.SC_SERVER_ERROR, ErrorResponse.FAILED_TO_GET_CREDENTIAL);
        }
    }

    public void persistCredentials(
            List<VerifiableCredential> credentials,
            String ipvSessionId,
            boolean receivedThisSession)
            throws VerifiableCredentialException {
        try {
            if (configService.enabled(SESSION_CREDENTIALS_TABLE_WRITES)) {
                for (var credential : credentials) {
                    dataStore.create(
                            credential.toSessionCredentialItem(ipvSessionId, receivedThisSession),
                            ConfigurationVariable.SESSION_CREDENTIALS_TTL);
                }
            }
        } catch (Exception e) {
            LOGGER.error(LogHelper.buildErrorMessage("Error persisting session credential", e));
            throw new VerifiableCredentialException(
                    HTTPResponse.SC_SERVER_ERROR, ErrorResponse.FAILED_TO_SAVE_CREDENTIAL);
        }
    }

    public void deleteSessionCredentials(String ipvSessionId) throws VerifiableCredentialException {
        LOGGER.info(
                LogHelper.buildLogMessage(
                        "Deleting credentials for current session from session credentials table"));
        try {
            dataStore.deleteAllByPartition(ipvSessionId);
        } catch (Exception e) {
            LOGGER.error(LogHelper.buildErrorMessage("Error deleting session credentials", e));
            throw new VerifiableCredentialException(
                    HTTPResponse.SC_SERVER_ERROR, ErrorResponse.FAILED_TO_DELETE_CREDENTIAL);
        }
    }
}
