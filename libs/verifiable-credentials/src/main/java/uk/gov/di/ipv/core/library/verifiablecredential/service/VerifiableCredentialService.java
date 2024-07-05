package uk.gov.di.ipv.core.library.verifiablecredential.service;

import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.config.EnvironmentVariable;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.exceptions.BatchDeleteException;
import uk.gov.di.ipv.core.library.exceptions.CredentialParseException;
import uk.gov.di.ipv.core.library.exceptions.VerifiableCredentialException;
import uk.gov.di.ipv.core.library.persistence.DataStore;
import uk.gov.di.ipv.core.library.persistence.item.VcStoreItem;
import uk.gov.di.ipv.core.library.service.ConfigService;

import java.util.ArrayList;
import java.util.List;

import static com.nimbusds.oauth2.sdk.http.HTTPResponse.SC_SERVER_ERROR;
import static uk.gov.di.ipv.core.library.domain.Cri.HMRC_MIGRATION;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.FAILED_TO_DELETE_CREDENTIAL;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.FAILED_TO_STORE_IDENTITY;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.FAILED_TO_UPDATE_IDENTITY;

public class VerifiableCredentialService {
    private static final Logger LOGGER = LogManager.getLogger();
    private final DataStore<VcStoreItem> dataStore;

    public VerifiableCredentialService(DataStore<VcStoreItem> dataStore) {
        this.dataStore = dataStore;
    }

    @ExcludeFromGeneratedCoverageReport
    public VerifiableCredentialService(ConfigService configService) {
        this.dataStore =
                DataStore.create(
                        configService.getEnvironmentVariable(
                                EnvironmentVariable.USER_ISSUED_CREDENTIALS_TABLE_NAME),
                        VcStoreItem.class,
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
            if (HMRC_MIGRATION.equals(vc.getCri())) {
                deleteVcStoreItem(vc.getUserId(), vc.getCri().getId());
            }
        }
    }

    private void deleteVcStoreItem(String userId, String criId) {
        dataStore.delete(userId, criId);
    }

    public void storeIdentity(List<VerifiableCredential> vcs, String userId)
            throws VerifiableCredentialException {
        try {
            dataStore.deleteAllByPartition(userId);
            vcs.stream().map(VerifiableCredential::toVcStoreItem).forEach(dataStore::create);
        } catch (BatchDeleteException e) {
            throw new VerifiableCredentialException(
                    HTTPResponse.SC_SERVER_ERROR, FAILED_TO_DELETE_CREDENTIAL);
        } catch (Exception e) {
            throw new VerifiableCredentialException(SC_SERVER_ERROR, FAILED_TO_STORE_IDENTITY);
        }
    }

    public void updateIdentity(List<VerifiableCredential> vcs)
            throws VerifiableCredentialException {
        try {
            vcs.stream().map(VerifiableCredential::toVcStoreItem).forEach(dataStore::update);
        } catch (Exception e) {
            throw new VerifiableCredentialException(SC_SERVER_ERROR, FAILED_TO_UPDATE_IDENTITY);
        }
    }
}
