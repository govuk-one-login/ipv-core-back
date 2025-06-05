package uk.gov.di.ipv.core.library.verifiablecredential.service;

import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.config.EnvironmentVariable;
import uk.gov.di.ipv.core.library.domain.Cri;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.enums.SessionCredentialsResetType;
import uk.gov.di.ipv.core.library.exceptions.CredentialParseException;
import uk.gov.di.ipv.core.library.exceptions.VerifiableCredentialException;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.persistence.DataStore;
import uk.gov.di.ipv.core.library.persistence.item.SessionCredentialItem;
import uk.gov.di.ipv.core.library.service.ConfigService;

import java.util.ArrayList;
import java.util.List;

import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.SESSION_CREDENTIALS_TTL;
import static uk.gov.di.ipv.core.library.domain.Cri.ADDRESS;
import static uk.gov.di.ipv.core.library.domain.Cri.DCMAW;
import static uk.gov.di.ipv.core.library.domain.Cri.EXPERIAN_FRAUD;

public class SessionCredentialsService {
    private static final Logger LOGGER = LogManager.getLogger();
    private static final String RECEIVED_THIS_SESSION = "receivedThisSession";
    private final DataStore<SessionCredentialItem> dataStore;

    public SessionCredentialsService(DataStore<SessionCredentialItem> dataStore) {
        this.dataStore = dataStore;
    }

    @ExcludeFromGeneratedCoverageReport
    public SessionCredentialsService(ConfigService configService) {
        this.dataStore =
                DataStore.create(
                        EnvironmentVariable.SESSION_CREDENTIALS_TABLE_NAME,
                        SessionCredentialItem.class,
                        configService);
    }

    public List<VerifiableCredential> getCredentials(String ipvSessionId, String userId)
            throws VerifiableCredentialException {
        return getCredentials(ipvSessionId, userId, null);
    }

    public List<VerifiableCredential> getCredentials(
            String ipvSessionId, String userId, Boolean receivedThisSession)
            throws VerifiableCredentialException {
        try {
            var verifiableCredentialList = new ArrayList<VerifiableCredential>();
            var credentials =
                    receivedThisSession != null
                            ? dataStore.getItemsWithBooleanAttribute(
                                    ipvSessionId, RECEIVED_THIS_SESSION, receivedThisSession)
                            : dataStore.getItems(ipvSessionId);
            for (var credential : credentials) {
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
            for (var credential : credentials) {
                dataStore.create(
                        credential.toSessionCredentialItem(ipvSessionId, receivedThisSession),
                        SESSION_CREDENTIALS_TTL);
            }
        } catch (Exception e) {
            LOGGER.error(LogHelper.buildErrorMessage("Error persisting session credential", e));
            throw new VerifiableCredentialException(
                    HTTPResponse.SC_SERVER_ERROR, ErrorResponse.FAILED_TO_SAVE_CREDENTIAL);
        }
    }

    public void deleteSessionCredentialsForResetType(
            String ipvSessionId, SessionCredentialsResetType resetType)
            throws VerifiableCredentialException {
        try {
            var sessionCredentialItems = dataStore.getItems(ipvSessionId);
            var vcsToDelete =
                    switch (resetType) {
                        case ALL, PENDING_F2F_ALL, REINSTATE -> sessionCredentialItems;
                        case ADDRESS_ONLY_CHANGE ->
                                sessionCredentialItems.stream()
                                        .filter(
                                                item ->
                                                        List.of(
                                                                        ADDRESS.getId(),
                                                                        EXPERIAN_FRAUD.getId())
                                                                .contains(item.getCriId()))
                                        .toList();
                        case DCMAW, PENDING_DCMAW_ALL ->
                                sessionCredentialItems.stream()
                                        .filter(item -> DCMAW.getId().equals(item.getCriId()))
                                        .toList();
                        case NAME_ONLY_CHANGE ->
                                sessionCredentialItems.stream()
                                        .filter(item -> !item.getCriId().equals(ADDRESS.getId()))
                                        .toList();
                    };

            dataStore.delete(vcsToDelete);
        } catch (Exception e) {
            LOGGER.error(
                    LogHelper.buildErrorMessage(
                            String.format(
                                    "Error deleting session credentials for subjourney: %s",
                                    resetType),
                            e));
            throw new VerifiableCredentialException(
                    HTTPResponse.SC_SERVER_ERROR, ErrorResponse.FAILED_TO_DELETE_CREDENTIAL);
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

    public void deleteSessionCredentialsForCri(String ipvSessionId, Cri cri)
            throws VerifiableCredentialException {
        var criId = cri.getId();
        try {
            List<SessionCredentialItem> itemsToDelete =
                    dataStore.getItemsBySortKeyPrefix(ipvSessionId, criId);
            dataStore.delete(itemsToDelete);
            LOGGER.info(
                    LogHelper.buildLogMessage(
                            String.format(
                                    "Deleted %d credentials for %s from session credentials table",
                                    itemsToDelete.size(), criId)));
        } catch (Exception e) {
            LOGGER.error(
                    LogHelper.buildErrorMessage(
                            String.format("Error deleting session credentials for CRI: %s", criId),
                            e));
            throw new VerifiableCredentialException(
                    HTTPResponse.SC_SERVER_ERROR, ErrorResponse.FAILED_TO_DELETE_CREDENTIAL);
        }
    }
}
