package uk.gov.di.ipv.core.library.verifiablecredential.service;

import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.lambda.powertools.tracing.Tracing;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.config.EnvironmentVariable;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.exceptions.BatchProcessingException;
import uk.gov.di.ipv.core.library.exceptions.CredentialParseException;
import uk.gov.di.ipv.core.library.exceptions.VerifiableCredentialException;
import uk.gov.di.ipv.core.library.persistence.DataStore;
import uk.gov.di.ipv.core.library.persistence.item.VcStoreItem;
import uk.gov.di.ipv.core.library.service.ConfigService;

import java.util.ArrayList;
import java.util.List;

import static com.nimbusds.oauth2.sdk.http.HTTPResponse.SC_SERVER_ERROR;
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
                        EnvironmentVariable.USER_ISSUED_CREDENTIALS_TABLE_NAME,
                        VcStoreItem.class,
                        configService);
    }

    @Tracing
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

    @Tracing
    public List<VerifiableCredential> getVcs(String userId) throws CredentialParseException {
        var vcs = new ArrayList<VerifiableCredential>();
        for (var vcStoreItem : dataStore.getItems(userId)) {
            vcs.add(VerifiableCredential.fromVcStoreItem(vcStoreItem));
        }
        return vcs;
    }

    @Tracing
    public VerifiableCredential getVc(String userId, String criId) throws CredentialParseException {
        return VerifiableCredential.fromVcStoreItem(dataStore.getItem(userId, criId));
    }

    @Tracing
    public void deleteVCs(String userId) throws VerifiableCredentialException {
        try {
            dataStore.deleteAllByPartition(userId);
        } catch (Exception e) {
            throw new VerifiableCredentialException(SC_SERVER_ERROR, FAILED_TO_DELETE_CREDENTIAL);
        }
    }

    @Tracing
    public void storeIdentity(List<VerifiableCredential> vcs, String userId)
            throws VerifiableCredentialException {
        try {
            dataStore.deleteAllByPartition(userId);
            vcs.stream().map(VerifiableCredential::toVcStoreItem).forEach(dataStore::create);
        } catch (BatchProcessingException e) {
            throw new VerifiableCredentialException(
                    HTTPResponse.SC_SERVER_ERROR, FAILED_TO_DELETE_CREDENTIAL);
        } catch (Exception e) {
            throw new VerifiableCredentialException(SC_SERVER_ERROR, FAILED_TO_STORE_IDENTITY);
        }
    }

    @Tracing
    public void updateIdentity(List<VerifiableCredential> vcs)
            throws VerifiableCredentialException {
        try {
            vcs.stream().map(VerifiableCredential::toVcStoreItem).forEach(dataStore::update);
        } catch (Exception e) {
            throw new VerifiableCredentialException(SC_SERVER_ERROR, FAILED_TO_UPDATE_IDENTITY);
        }
    }
}
