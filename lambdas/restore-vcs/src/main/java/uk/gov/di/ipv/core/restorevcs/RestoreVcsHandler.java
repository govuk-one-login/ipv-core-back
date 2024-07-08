package uk.gov.di.ipv.core.restorevcs;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestStreamHandler;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.awssdk.services.dynamodb.model.ConditionalCheckFailedException;
import software.amazon.lambda.powertools.logging.Logging;
import software.amazon.lambda.powertools.tracing.Tracing;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.auditing.AuditEvent;
import uk.gov.di.ipv.core.library.auditing.AuditEventTypes;
import uk.gov.di.ipv.core.library.auditing.AuditEventUser;
import uk.gov.di.ipv.core.library.auditing.extension.AuditExtensionsVcEvidence;
import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
import uk.gov.di.ipv.core.library.config.EnvironmentVariable;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.UserIdCriIdPair;
import uk.gov.di.ipv.core.library.domain.VcsActionRequest;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.exceptions.CredentialAlreadyExistsException;
import uk.gov.di.ipv.core.library.exceptions.CredentialParseException;
import uk.gov.di.ipv.core.library.exceptions.SqsException;
import uk.gov.di.ipv.core.library.exceptions.UnrecognisedVotException;
import uk.gov.di.ipv.core.library.exceptions.VerifiableCredentialException;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.persistence.DataStore;
import uk.gov.di.ipv.core.library.persistence.item.VcStoreItem;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.restorevcs.exceptions.RestoreVcException;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.List;

import static uk.gov.di.ipv.core.library.auditing.helpers.AuditExtensionsHelper.getExtensionsForAudit;

@ExcludeFromGeneratedCoverageReport
@SuppressWarnings("unused") // Temporarily disable to pass sonarqube
public class RestoreVcsHandler implements RequestStreamHandler {
    private static final Logger LOGGER = LogManager.getLogger();
    private final ConfigService configService;
    private final DataStore<VcStoreItem> vcDataStore;
    private final DataStore<VcStoreItem> archivedVcDataStore;
    private final AuditService auditService;

    @SuppressWarnings("unused") // Used through dependency injection
    public RestoreVcsHandler(
            ConfigService configService,
            DataStore<VcStoreItem> vcDataStore,
            DataStore<VcStoreItem> archivedVcDataStore,
            AuditService auditService) {
        this.configService = configService;
        this.vcDataStore = vcDataStore;
        this.archivedVcDataStore = archivedVcDataStore;
        this.auditService = auditService;
    }

    @SuppressWarnings("unused") // Used by AWS
    public RestoreVcsHandler() {
        this.configService = new ConfigService();
        this.vcDataStore =
                new DataStore<>(
                        this.configService.getEnvironmentVariable(
                                EnvironmentVariable.USER_ISSUED_CREDENTIALS_TABLE_NAME),
                        VcStoreItem.class,
                        DataStore.getClient(),
                        configService);
        this.archivedVcDataStore =
                new DataStore<>(
                        this.configService.getEnvironmentVariable(
                                EnvironmentVariable.REVOKED_USER_CREDENTIALS_TABLE_NAME),
                        VcStoreItem.class,
                        DataStore.getClient(),
                        configService);
        this.auditService = new AuditService(AuditService.getSqsClients(), configService);
    }

    @Override
    @Logging(clearState = true)
    @Tracing
    public void handleRequest(InputStream inputStream, OutputStream outputStream, Context context)
            throws IOException {
        LogHelper.attachComponentId(configService);
        var userIdCriIdPairs =
                new ObjectMapper()
                        .readValue(inputStream, VcsActionRequest.class)
                        .getUserIdCriIdPairs();
        LOGGER.info(
                LogHelper.buildLogMessage(
                        String.format("Restoring %s VCs.", userIdCriIdPairs.size())));

        try {
            restore(userIdCriIdPairs);
            LOGGER.info(
                    LogHelper.buildLogMessage(
                            String.format(
                                    "Finished attempt to restore %s VCs.",
                                    userIdCriIdPairs.size())));
        } catch (SqsException e) {
            LOGGER.error(
                    LogHelper.buildErrorMessage(
                            "Stopped restoring VCs because of failure to send audit event", e));
        } finally {
            auditService.awaitAuditEvents();
        }
    }

    private void restore(List<UserIdCriIdPair> userIdCriIdPairs) throws SqsException {
        var numberOfVcs = userIdCriIdPairs.size();

        // Iterate over each VC
        for (int i = 0; i < numberOfVcs; i++) {
            var userIdCriIdPair = userIdCriIdPairs.get(i);
            LOGGER.info(
                    LogHelper.buildLogMessage(
                            String.format("Restoring VC (%s / %s)", i + 1, numberOfVcs)));

            try {
                restore(userIdCriIdPair);
                LOGGER.info(
                        LogHelper.buildLogMessage(
                                String.format(
                                        "Successfully restored VC (%s / %s)", i + 1, numberOfVcs)));
            } catch (SqsException e) {
                throw new SqsException(
                        String.format(
                                "Failed to send audit event IPV_VC_RESTORED (%s / %s): %s",
                                i + 1, numberOfVcs, e.getMessage()));
            } catch (CredentialAlreadyExistsException e) {
                LOGGER.info(
                        LogHelper.buildErrorMessage(
                                String.format(
                                        "Skipped overwrite of existing VC (%s / %s)",
                                        i + 1, numberOfVcs),
                                e));
            } catch (Exception e) {
                LOGGER.error(
                        LogHelper.buildErrorMessage(
                                String.format(
                                        "Unexpected error occurred (%s / %s)", i + 1, numberOfVcs),
                                e));
            }
        }
    }

    private void restore(UserIdCriIdPair userIdCriIdPair)
            throws VerifiableCredentialException, CredentialAlreadyExistsException, SqsException,
                    RestoreVcException, UnrecognisedVotException, CredentialParseException {
        // Read VC with userId and CriId
        var archivedVc =
                archivedVcDataStore.getItem(
                        userIdCriIdPair.getUserId(), userIdCriIdPair.getCriId());

        if (archivedVc != null) {
            // Restore VC if empty
            createVcStoreItemIfNotExists(archivedVc);

            // Send audit event
            sendVcRestoredAuditEvent(userIdCriIdPair.getUserId(), archivedVc);

            // Delete VC from the archive table
            archivedVcDataStore.delete(userIdCriIdPair.getUserId(), userIdCriIdPair.getCriId());
        } else {
            throw new RestoreVcException("VC cannot be found");
        }
    }

    public void createVcStoreItemIfNotExists(
            VcStoreItem vcStoreItem) // moved from verifiableCredentialService
            throws VerifiableCredentialException, CredentialAlreadyExistsException {
        try {
            vcDataStore.createIfNotExists(vcStoreItem);
        } catch (ConditionalCheckFailedException e) {
            throw new CredentialAlreadyExistsException();
        } catch (Exception e) {
            LOGGER.error("Error persisting user credential: {}", e.getMessage(), e);
            throw new VerifiableCredentialException(
                    HTTPResponse.SC_SERVER_ERROR, ErrorResponse.FAILED_TO_SAVE_CREDENTIAL);
        }
    }

    private void sendVcRestoredAuditEvent(String userId, VcStoreItem vcStoreItem)
            throws SqsException, UnrecognisedVotException, CredentialParseException {
        var auditEventUser = new AuditEventUser(userId, null, null, null);

        AuditExtensionsVcEvidence auditExtensions =
                getExtensionsForAudit(VerifiableCredential.fromVcStoreItem(vcStoreItem), null);

        var auditEvent =
                AuditEvent.createWithoutDeviceInformation(
                        AuditEventTypes.IPV_VC_RESTORED,
                        configService.getSsmParameter(ConfigurationVariable.COMPONENT_ID),
                        auditEventUser,
                        auditExtensions);
        auditService.sendAuditEvent(auditEvent);
    }
}
