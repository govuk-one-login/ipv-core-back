package uk.gov.di.ipv.core.revokevcs;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestStreamHandler;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.lambda.powertools.logging.Logging;
import software.amazon.lambda.powertools.tracing.Tracing;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.auditing.AuditEvent;
import uk.gov.di.ipv.core.library.auditing.AuditEventTypes;
import uk.gov.di.ipv.core.library.auditing.AuditEventUser;
import uk.gov.di.ipv.core.library.auditing.extension.AuditExtensionCriId;
import uk.gov.di.ipv.core.library.auditing.extension.AuditExtensionsVcEvidence;
import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
import uk.gov.di.ipv.core.library.config.EnvironmentVariable;
import uk.gov.di.ipv.core.library.domain.UserIdCriIdPair;
import uk.gov.di.ipv.core.library.domain.VcsActionRequest;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.exceptions.AuditExtensionException;
import uk.gov.di.ipv.core.library.exceptions.CredentialParseException;
import uk.gov.di.ipv.core.library.exceptions.SqsException;
import uk.gov.di.ipv.core.library.exceptions.UnrecognisedVotException;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.persistence.DataStore;
import uk.gov.di.ipv.core.library.persistence.item.VcStoreItem;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.verifiablecredential.service.VerifiableCredentialService;
import uk.gov.di.ipv.core.revokevcs.domain.RevokeVcsResult;
import uk.gov.di.ipv.core.revokevcs.exceptions.RevokeVcException;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.List;

import static uk.gov.di.ipv.core.library.auditing.helpers.AuditExtensionsHelper.getExtensionsForAudit;

@ExcludeFromGeneratedCoverageReport
@SuppressWarnings("unused") // Temporarily disable to pass sonarqube
public class RevokeVcsHandler implements RequestStreamHandler {
    private static final Logger LOGGER = LogManager.getLogger();
    private static final ObjectMapper objectMapper = new ObjectMapper();
    private final ConfigService configService;
    private final DataStore<VcStoreItem> vcDataStore;
    private final DataStore<VcStoreItem> archivedVcDataStore;
    private final AuditService auditService;

    @SuppressWarnings("unused") // Used through dependency injection
    public RevokeVcsHandler(
            ConfigService configService,
            VerifiableCredentialService verifiableCredentialService,
            DataStore<VcStoreItem> vcDataStore,
            DataStore<VcStoreItem> archivedVcDataStore,
            AuditService auditService) {
        this.configService = configService;
        this.vcDataStore = vcDataStore;
        this.archivedVcDataStore = archivedVcDataStore;
        this.auditService = auditService;
    }

    @SuppressWarnings("unused") // Used by AWS
    public RevokeVcsHandler() {
        this.configService = new ConfigService();
        boolean isRunningLocally = this.configService.isRunningLocally();
        this.vcDataStore =
                new DataStore<>(
                        this.configService.getEnvironmentVariable(
                                EnvironmentVariable.USER_ISSUED_CREDENTIALS_TABLE_NAME),
                        VcStoreItem.class,
                        DataStore.getClient(isRunningLocally),
                        isRunningLocally,
                        configService);
        this.archivedVcDataStore =
                new DataStore<>(
                        this.configService.getEnvironmentVariable(
                                EnvironmentVariable.REVOKED_USER_CREDENTIALS_TABLE_NAME),
                        VcStoreItem.class,
                        DataStore.getClient(isRunningLocally),
                        isRunningLocally,
                        configService);
        this.auditService = new AuditService(AuditService.getDefaultSqsClient(), configService);
    }

    @Override
    @Tracing
    @Logging(clearState = true)
    public void handleRequest(InputStream inputStream, OutputStream outputStream, Context context)
            throws IOException {
        LogHelper.attachComponentId(configService);
        var userIdCriIdPairs =
                new ObjectMapper()
                        .readValue(inputStream, VcsActionRequest.class)
                        .getUserIdCriIdPairs();
        var result = new RevokeVcsResult();
        LOGGER.info(
                LogHelper.buildLogMessage(
                        String.format("Revoking %s VCs.", userIdCriIdPairs.size())));

        try {
            revoke(userIdCriIdPairs, result);
            LOGGER.info(
                    LogHelper.buildLogMessage(
                            String.format(
                                    "Finished attempt to revoke %s VCs.",
                                    userIdCriIdPairs.size())));
        } catch (SqsException e) {
            LOGGER.error(
                    LogHelper.buildErrorMessage(
                            "Stopped revoking VCs because of failure to send audit event.", e));
        } finally {
            objectMapper.enable(SerializationFeature.INDENT_OUTPUT);
            objectMapper.writeValue(outputStream, result);
        }
    }

    private void revoke(List<UserIdCriIdPair> userIdCriIdPairs, RevokeVcsResult result)
            throws SqsException {
        var numberOfVcs = userIdCriIdPairs.size();

        // Iterate over each VC
        for (int i = 0; i < numberOfVcs; i++) {
            var userIdCriIdPair = userIdCriIdPairs.get(i);
            LOGGER.info(
                    LogHelper.buildLogMessage(
                            String.format("Revoking VC (%s / %s)", i + 1, numberOfVcs)));

            try {
                revoke(userIdCriIdPair);
                LOGGER.info(
                        LogHelper.buildLogMessage(
                                String.format(
                                        "Successfully revoked VC (%s / %s)", i + 1, numberOfVcs)));
                result.addSuccess(userIdCriIdPair);
            } catch (Exception e) {
                LOGGER.error(
                        LogHelper.buildErrorMessage(
                                String.format(
                                        "Unexpected error occurred (%s / %s)", i + 1, numberOfVcs),
                                e));
                result.addFailure(userIdCriIdPair, e);
                sendRevokedFailureAuditEvent(
                        userIdCriIdPair.getUserId(), userIdCriIdPair.getCriId(), i, numberOfVcs);
            }
        }
    }

    private void revoke(UserIdCriIdPair userIdCriIdPair)
            throws SqsException, RevokeVcException, AuditExtensionException,
                    UnrecognisedVotException, CredentialParseException {
        // Read VC with userId and CriId
        var vcStoreItem =
                vcDataStore.getItem(userIdCriIdPair.getUserId(), userIdCriIdPair.getCriId());

        if (vcStoreItem != null) {
            // Archive VC
            archivedVcDataStore.create(vcStoreItem);

            // Send audit event
            sendVcRevokedAuditEvent(userIdCriIdPair.getUserId(), vcStoreItem);

            // Delete VC from the main table
            vcDataStore.delete(userIdCriIdPair.getUserId(), userIdCriIdPair.getCriId());
        } else {
            throw new RevokeVcException("VC cannot be found");
        }
    }

    private void sendVcRevokedAuditEvent(String userId, VcStoreItem vcStoreItem)
            throws SqsException, AuditExtensionException, UnrecognisedVotException,
                    CredentialParseException {
        var auditEventUser = new AuditEventUser(userId, null, null, null);

        AuditExtensionsVcEvidence auditExtensions =
                getExtensionsForAudit(VerifiableCredential.fromVcStoreItem(vcStoreItem), null);
        var auditEvent =
                new AuditEvent(
                        AuditEventTypes.IPV_VC_REVOKED,
                        configService.getSsmParameter(ConfigurationVariable.COMPONENT_ID),
                        auditEventUser,
                        auditExtensions);
        auditService.sendAuditEvent(auditEvent);
    }

    private void sendRevokedFailureAuditEvent(String userId, String criId, int i, int numberOfVcs)
            throws SqsException {
        var auditEventUser = new AuditEventUser(userId, null, null, null);

        var auditExtensions = new AuditExtensionCriId(criId);
        var auditEvent =
                new AuditEvent(
                        AuditEventTypes.IPV_VC_REVOKED_FAILURE,
                        configService.getSsmParameter(ConfigurationVariable.COMPONENT_ID),
                        auditEventUser,
                        auditExtensions);
        try {
            auditService.sendAuditEvent(auditEvent);
        } catch (SqsException e) {
            throw new SqsException(
                    String.format(
                            "Failed to send audit event IPV_VC_REVOKED_FAILURE (%s / %s): %s",
                            i + 1, numberOfVcs, e.getMessage()));
        }
    }
}
