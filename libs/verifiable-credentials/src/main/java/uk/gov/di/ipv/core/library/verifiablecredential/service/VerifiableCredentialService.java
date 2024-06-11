package uk.gov.di.ipv.core.library.verifiablecredential.service;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.message.StringMapMessage;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.config.EnvironmentVariable;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.exceptions.CredentialParseException;
import uk.gov.di.ipv.core.library.exceptions.VerifiableCredentialException;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.persistence.DataStore;
import uk.gov.di.ipv.core.library.persistence.item.VcStoreItem;
import uk.gov.di.ipv.core.library.service.ConfigService;

import java.util.ArrayList;
import java.util.List;

import static com.nimbusds.oauth2.sdk.http.HTTPResponse.SC_SERVER_ERROR;
import static uk.gov.di.ipv.core.library.domain.CriIdentifer.HMRC_MIGRATION;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.FAILED_TO_STORE_IDENTITY;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_MESSAGE_DESCRIPTION;

public class VerifiableCredentialService {
    private static final Logger LOGGER = LogManager.getLogger();
    private final DataStore<VcStoreItem> dataStore;

    public VerifiableCredentialService(DataStore<VcStoreItem> dataStore) {
        this.dataStore = dataStore;
    }

    @ExcludeFromGeneratedCoverageReport
    public VerifiableCredentialService(ConfigService configService) {
        this.dataStore =
                new DataStore<>(
                        configService.getEnvironmentVariable(
                                EnvironmentVariable.USER_ISSUED_CREDENTIALS_TABLE_NAME),
                        VcStoreItem.class,
                        DataStore.getClient(),
                        configService);
    }

    public void persistUserCredentials(VerifiableCredential vc)
            throws VerifiableCredentialException {
        try {
            dataStore.create(vc.toVcStoreItem());
        } catch (Exception e) {
            LOGGER.error("Error persisting user credential: {}", e.getMessage(), e);
            throw new VerifiableCredentialException(
                    SC_SERVER_ERROR, ErrorResponse.FAILED_TO_SAVE_CREDENTIAL);
        }
    }

    public List<VerifiableCredential> getVcs(String userId) throws CredentialParseException {
        var vcs = new ArrayList<VerifiableCredential>();
        for (var vcStoreItem : dataStore.getItems(userId)) {
            vcs.add(VerifiableCredential.fromVcStoreItem(vcStoreItem));
        }
        return vcs;
    }

    public VerifiableCredential getVc(String userId, String criId) throws CredentialParseException {
        return VerifiableCredential.fromVcStoreItem(dataStore.getItem(userId, criId));
    }

    public void deleteHmrcInheritedIdentityIfPresent(List<VerifiableCredential> vcs) {
        for (var vc : vcs) {
            if (HMRC_MIGRATION.getId().equals(vc.getCriId())) {
                deleteVcStoreItem(vc.getUserId(), vc.getCriId());
            }
        }
    }

    public void deleteVcs(List<VerifiableCredential> vcs, Boolean isUserInitiated) {
        if (!vcs.isEmpty()) {
            var message =
                    new StringMapMessage()
                            .with(
                                    LOG_MESSAGE_DESCRIPTION.getFieldName(),
                                    "Deleting existing issued VCs.")
                            .with(
                                    LogHelper.LogField.LOG_NUMBER_OF_VCS.getFieldName(),
                                    String.valueOf(vcs.size()))
                            .with(
                                    LogHelper.LogField.LOG_IS_USER_INITIATED.getFieldName(),
                                    String.valueOf(isUserInitiated));
            LOGGER.info(message);
        }
        for (var vc : vcs) {
            deleteVcStoreItem(vc.getUserId(), vc.getCriId());
        }
    }

    public void deleteVcStoreItem(String userId, String criId) {
        dataStore.delete(userId, criId);
    }

    public void storeIdentity(List<VerifiableCredential> vcs, String userId)
            throws VerifiableCredentialException {
        try {
            dataStore.deleteAllByPartition(userId);
            vcs.stream().map(VerifiableCredential::toVcStoreItem).forEach(dataStore::create);
        } catch (Exception e) {
            throw new VerifiableCredentialException(SC_SERVER_ERROR, FAILED_TO_STORE_IDENTITY);
        }
    }
}
