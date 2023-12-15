package uk.gov.di.ipv.core.library.verifiablecredential.service;

import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.message.StringMapMessage;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
import uk.gov.di.ipv.core.library.config.EnvironmentVariable;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.exceptions.VerifiableCredentialException;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.persistence.DataStore;
import uk.gov.di.ipv.core.library.persistence.item.VcStoreItem;
import uk.gov.di.ipv.core.library.service.ConfigService;

import java.time.Instant;
import java.util.Date;
import java.util.List;

import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_MESSAGE_DESCRIPTION;

public class VerifiableCredentialService {
    private static final Logger LOGGER = LogManager.getLogger();
    private final DataStore<VcStoreItem> dataStore;
    private final ConfigService configService;

    @ExcludeFromGeneratedCoverageReport
    public VerifiableCredentialService(ConfigService configService) {
        this.configService = configService;
        boolean isRunningLocally = this.configService.isRunningLocally();
        this.dataStore =
                new DataStore<>(
                        this.configService.getEnvironmentVariable(
                                EnvironmentVariable.USER_ISSUED_CREDENTIALS_TABLE_NAME),
                        VcStoreItem.class,
                        DataStore.getClient(isRunningLocally),
                        isRunningLocally,
                        configService);
    }

    public VerifiableCredentialService(
            DataStore<VcStoreItem> dataStore, ConfigService configService) {
        this.configService = configService;
        this.dataStore = dataStore;
    }

    public void persistUserCredentials(
            SignedJWT credential, String credentialIssuerId, String userId)
            throws VerifiableCredentialException {
        try {
            VcStoreItem vcStoreItem = createVcStoreItem(credential, credentialIssuerId, userId);
            dataStore.create(vcStoreItem, ConfigurationVariable.VC_TTL);
        } catch (Exception e) {
            LOGGER.error("Error persisting user credential: {}", e.getMessage(), e);
            throw new VerifiableCredentialException(
                    HTTPResponse.SC_SERVER_ERROR, ErrorResponse.FAILED_TO_SAVE_CREDENTIAL);
        }
    }

    private VcStoreItem createVcStoreItem(
            SignedJWT credential, String credentialIssuerId, String userId)
            throws java.text.ParseException {
        VcStoreItem vcStoreItem =
                VcStoreItem.builder()
                        .userId(userId)
                        .credentialIssuer(credentialIssuerId)
                        .dateCreated(Instant.now())
                        .credential(credential.serialize())
                        .build();

        Date expirationTime = credential.getJWTClaimsSet().getExpirationTime();
        if (expirationTime != null) {
            vcStoreItem.setExpirationTime(expirationTime.toInstant());
        }
        return vcStoreItem;
    }

    public List<VcStoreItem> getVcStoreItems(String userId) {
        return dataStore.getItems(userId);
    }

    public VcStoreItem getVcStoreItem(String userId, String criId) {
        return dataStore.getItem(userId, criId);
    }

    public void deleteVcStoreItems(String userId, Boolean isUserInitiated) {
        List<VcStoreItem> vcStoreItems = getVcStoreItems(userId);
        if (!vcStoreItems.isEmpty()) {
            var message =
                    new StringMapMessage()
                            .with(
                                    LOG_MESSAGE_DESCRIPTION.getFieldName(),
                                    "Deleting existing issued VCs.")
                            .with(
                                    LogHelper.LogField.LOG_NUMBER_OF_VCS.getFieldName(),
                                    String.valueOf(vcStoreItems.size()))
                            .with(
                                    LogHelper.LogField.LOG_IS_USER_INITIATED.getFieldName(),
                                    String.valueOf(isUserInitiated));
            LOGGER.info(message);
        }
        for (VcStoreItem item : vcStoreItems) {
            deleteVcStoreItem(item.getUserId(), item.getCredentialIssuer());
        }
    }

    public void deleteVcStoreItem(String userId, String criId) {
        dataStore.delete(userId, criId);
    }
}
