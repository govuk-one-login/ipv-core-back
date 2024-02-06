package uk.gov.di.ipv.core.restorevcs;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestStreamHandler;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.shaded.json.JSONObject;
import com.nimbusds.jwt.SignedJWT;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.lambda.powertools.logging.Logging;
import software.amazon.lambda.powertools.tracing.Tracing;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.auditing.AuditEvent;
import uk.gov.di.ipv.core.library.auditing.AuditEventTypes;
import uk.gov.di.ipv.core.library.auditing.AuditEventUser;
import uk.gov.di.ipv.core.library.auditing.extension.AuditExtensionsVcEvidence;
import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
import uk.gov.di.ipv.core.library.config.EnvironmentVariable;
import uk.gov.di.ipv.core.library.domain.UserIdCriIdPair;
import uk.gov.di.ipv.core.library.domain.VcsActionRequest;
import uk.gov.di.ipv.core.library.exceptions.CredentialAlreadyExistsException;
import uk.gov.di.ipv.core.library.exceptions.SqsException;
import uk.gov.di.ipv.core.library.exceptions.VerifiableCredentialException;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.persistence.DataStore;
import uk.gov.di.ipv.core.library.persistence.item.VcStoreItem;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.verifiablecredential.helpers.VcHelper;
import uk.gov.di.ipv.core.library.verifiablecredential.service.VerifiableCredentialService;
import uk.gov.di.ipv.core.restorevcs.exceptions.RestoreVcException;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.text.ParseException;
import java.util.List;

@ExcludeFromGeneratedCoverageReport
@SuppressWarnings("unused") // Temporarily disable to pass sonarqube
public class RestoreVcsHandler implements RequestStreamHandler {
    private static final Logger LOGGER = LogManager.getLogger();
    private final ConfigService configService;
    private final VerifiableCredentialService verifiableCredentialService;
    private final DataStore<VcStoreItem> archivedVcDataStore;
    private final AuditService auditService;

    @SuppressWarnings("unused") // Used by AWS
    public RestoreVcsHandler(
            ConfigService configService,
            VerifiableCredentialService verifiableCredentialService,
            DataStore<VcStoreItem> archivedVcDataStore,
            AuditService auditService) {
        this.configService = configService;
        this.verifiableCredentialService = verifiableCredentialService;
        this.archivedVcDataStore = archivedVcDataStore;
        this.auditService = auditService;
    }

    @SuppressWarnings("unused") // Used through dependency injection
    public RestoreVcsHandler() {
        this.configService = new ConfigService();
        boolean isRunningLocally = this.configService.isRunningLocally();
        this.archivedVcDataStore =
                new DataStore<>(
                        this.configService.getEnvironmentVariable(
                                EnvironmentVariable.REVOKED_USER_CREDENTIALS_TABLE_NAME),
                        VcStoreItem.class,
                        DataStore.getClient(isRunningLocally),
                        isRunningLocally,
                        configService);
        this.verifiableCredentialService = new VerifiableCredentialService(configService);
        this.auditService = new AuditService(AuditService.getDefaultSqsClient(), configService);
    }

    @Override
    @Logging(clearState = true)
    @Tracing
    public void handleRequest(InputStream inputStream, OutputStream outputStream, Context context)
            throws IOException {
        LogHelper.attachComponentIdToLogs(configService);
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
            throws ParseException, VerifiableCredentialException, CredentialAlreadyExistsException,
                    SqsException, JsonProcessingException, RestoreVcException {
        // Read VC with userId and CriId
        var archivedVc =
                archivedVcDataStore.getItem(
                        userIdCriIdPair.getUserId(), userIdCriIdPair.getCriId());

        if (archivedVc != null) {
            // Restore VC if empty
            var signedArchivedVc = SignedJWT.parse(archivedVc.getCredential());
            verifiableCredentialService.persistUserCredentialsIfNotExists(
                    signedArchivedVc, userIdCriIdPair.getCriId(), userIdCriIdPair.getUserId());

            // Send audit event
            sendVcRestoredAuditEvent(userIdCriIdPair.getUserId(), archivedVc);

            // Delete VC from the archive table
            archivedVcDataStore.delete(userIdCriIdPair.getUserId(), userIdCriIdPair.getCriId());
        } else {
            throw new RestoreVcException("VC cannot be found");
        }
    }

    private void sendVcRestoredAuditEvent(String userId, VcStoreItem vcStoreItem)
            throws ParseException, SqsException, JsonProcessingException {
        var auditEventUser = new AuditEventUser(userId, null, null, null);

        var signedCredential = SignedJWT.parse(vcStoreItem.getCredential());
        var jwtClaimsSet = signedCredential.getJWTClaimsSet();
        var vc = (JSONObject) jwtClaimsSet.getClaim("vc");
        var evidence = vc.getAsString("evidence");

        var auditExtensions =
                new AuditExtensionsVcEvidence(
                        jwtClaimsSet.getIssuer(),
                        evidence,
                        null,
                        VcHelper.checkIfDocUKIssuedForCredential(
                                signedCredential, vcStoreItem.getCredentialIssuer()),
                        VcHelper.extractAgeFromCredential(signedCredential));
        var auditEvent =
                new AuditEvent(
                        AuditEventTypes.IPV_VC_RESTORED,
                        configService.getSsmParameter(ConfigurationVariable.COMPONENT_ID),
                        auditEventUser,
                        auditExtensions);
        auditService.sendAuditEvent(auditEvent);
    }
}
