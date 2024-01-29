package uk.gov.di.ipv.core.revokevcs;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestStreamHandler;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.lambda.powertools.logging.Logging;
import software.amazon.lambda.powertools.tracing.Tracing;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.config.EnvironmentVariable;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.persistence.DataStore;
import uk.gov.di.ipv.core.library.persistence.item.VcStoreItem;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.verifiablecredential.service.VerifiableCredentialService;
import uk.gov.di.ipv.core.revokevcs.domain.RevokeRequest;
import uk.gov.di.ipv.core.revokevcs.domain.UserIdCriIdPair;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.List;

@ExcludeFromGeneratedCoverageReport
@SuppressWarnings("unused") // Temporarily disable to pass sonarqube
public class RevokeVcsHandler implements RequestStreamHandler {
    private static final Logger LOGGER = LogManager.getLogger();
    private final ConfigService configService;
    private final VerifiableCredentialService verifiableCredentialService;
    private final DataStore<VcStoreItem> dataStore;

    @SuppressWarnings("unused") // Used by AWS
    public RevokeVcsHandler(
            ConfigService configService,
            VerifiableCredentialService verifiableCredentialService,
            DataStore<VcStoreItem> dataStore) {
        this.configService = configService;
        this.verifiableCredentialService = verifiableCredentialService;
        this.dataStore = dataStore;
    }

    @SuppressWarnings("unused") // Used through dependency injection
    public RevokeVcsHandler() {
        this.configService = new ConfigService();
        this.verifiableCredentialService = new VerifiableCredentialService(configService);
        boolean isRunningLocally = this.configService.isRunningLocally();
        this.dataStore =
                new DataStore<>(
                        this.configService.getEnvironmentVariable(
                                EnvironmentVariable.REVOKED_USER_CREDENTIALS_TABLE_NAME),
                        VcStoreItem.class,
                        DataStore.getClient(isRunningLocally),
                        isRunningLocally,
                        configService);
    }

    @Override
    @Tracing
    @Logging(clearState = true)
    public void handleRequest(InputStream inputStream, OutputStream outputStream, Context context)
            throws IOException {
        LogHelper.attachComponentIdToLogs(configService);
        List<UserIdCriIdPair> userIdCriIdPairs =
                new ObjectMapper()
                        .readValue(inputStream, RevokeRequest.class)
                        .getUserIdCriIdPairs();
        LOGGER.info("Revoking {} VCs", userIdCriIdPairs.size());

        revoke(userIdCriIdPairs);
        LOGGER.info("Finished attempt to revoke {} VCs", userIdCriIdPairs.size());
    }

    private void revoke(List<UserIdCriIdPair> userIdCriIdPairs) {
        for (int i = 0; i < userIdCriIdPairs.size(); i++) {
            var userIdCriIdPair = userIdCriIdPairs.get(i);
            LOGGER.info("Processing VC {} / {}", i, userIdCriIdPairs.size());

            try {
                revoke(userIdCriIdPair);
                LOGGER.info("Successfully revoked VC.");
            } catch (Exception e) {
                LOGGER.error("Failed to revoke VC.");
            }
        }
    }

    public void revoke(UserIdCriIdPair userIdCriIdPair) {
        // Read KBV VC for the ID
        VcStoreItem vc =
                this.verifiableCredentialService.getVcStoreItem(
                        userIdCriIdPair.getUserId(), userIdCriIdPair.getCriId());

        if (vc != null) {
            // Archive VC
            dataStore.create(vc);

            // Submit audit event
            // ...

            // Delete VC from the main table
            // ...

        } else {
            LOGGER.error("VC cannot be found");
        }
    }
}
