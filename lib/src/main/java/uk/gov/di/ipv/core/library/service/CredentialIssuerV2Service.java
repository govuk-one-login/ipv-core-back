package uk.gov.di.ipv.core.library.service;

import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.domain.CredentialIssuerException;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.persistence.DataStore;
import uk.gov.di.ipv.core.library.persistence.item.UserIssuedCredentialsV2Item;

import java.time.LocalDateTime;

import static uk.gov.di.ipv.core.library.config.EnvironmentVariable.USER_ISSUED_CREDENTIALS_V2_TABLE_NAME;

public class CredentialIssuerV2Service {

    private static final Logger LOGGER = LogManager.getLogger();

    private final DataStore<UserIssuedCredentialsV2Item> dataStore;
    private final ConfigurationService configurationService;

    @ExcludeFromGeneratedCoverageReport
    public CredentialIssuerV2Service(ConfigurationService configurationService) {
        this.configurationService = configurationService;
        boolean isRunningLocally = this.configurationService.isRunningLocally();
        this.dataStore =
                new DataStore<>(
                        this.configurationService.getEnvironmentVariable(
                                USER_ISSUED_CREDENTIALS_V2_TABLE_NAME),
                        UserIssuedCredentialsV2Item.class,
                        DataStore.getClient(isRunningLocally),
                        isRunningLocally,
                        configurationService);
    }

    public CredentialIssuerV2Service(
            DataStore<UserIssuedCredentialsV2Item> dataStore,
            ConfigurationService configurationService) {
        this.configurationService = configurationService;
        this.dataStore = dataStore;
    }

    public void persistUserCredentials(
            String credential, String credentialIssuerId, String userId) {
        UserIssuedCredentialsV2Item userIssuedCredentials = new UserIssuedCredentialsV2Item();
        userIssuedCredentials.setUserId(userId);
        userIssuedCredentials.setCredentialIssuer(credentialIssuerId);
        userIssuedCredentials.setCredential(credential);
        userIssuedCredentials.setDateCreated(LocalDateTime.now());
        try {
            dataStore.create(userIssuedCredentials);
        } catch (UnsupportedOperationException e) {
            LOGGER.error("Error persisting V2 user credential: {}", e.getMessage(), e);
            throw new CredentialIssuerException(
                    HTTPResponse.SC_SERVER_ERROR, ErrorResponse.FAILED_TO_SAVE_CREDENTIAL);
        }
    }
}
