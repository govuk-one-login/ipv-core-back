package uk.gov.di.ipv.core.bulkmigratevcs;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.lambda.powertools.logging.Logging;
import uk.gov.di.ipv.core.bulkmigratevcs.domain.BatchSummary;
import uk.gov.di.ipv.core.bulkmigratevcs.domain.EvcsMetadata;
import uk.gov.di.ipv.core.bulkmigratevcs.domain.Report;
import uk.gov.di.ipv.core.bulkmigratevcs.domain.Request;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.client.EvcsClient;
import uk.gov.di.ipv.core.library.config.EnvironmentVariable;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.dto.EvcsCreateUserVCsDto;
import uk.gov.di.ipv.core.library.enums.Vot;
import uk.gov.di.ipv.core.library.exception.EvcsServiceException;
import uk.gov.di.ipv.core.library.exceptions.VerifiableCredentialException;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.persistence.DynamoDataStore;
import uk.gov.di.ipv.core.library.persistence.ScanDynamoDataStore;
import uk.gov.di.ipv.core.library.persistence.item.ReportUserIdentityItem;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.verifiablecredential.service.VerifiableCredentialService;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ForkJoinPool;

import static uk.gov.di.ipv.core.library.enums.EvcsVCState.CURRENT;
import static uk.gov.di.ipv.core.library.enums.EvcsVcProvenance.MIGRATED;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_BATCH_ID;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_ERROR_DESCRIPTION;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_HASH_USER_ID;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_VOT;

public class BulkMigrateVcsHandler implements RequestHandler<Request, Report> {
    private static final Logger LOGGER = LogManager.getLogger();
    private static final String HASH_USER_ID = "hashUserId";
    private static final String USER_ID = "userId";
    private static final String IDENTITY = "identity";
    public static final int DEFAULT_PARALLELISM = 4;
    public static final int ONE_MINUTE_IN_MS = 60_000;
    private final ScanDynamoDataStore<ReportUserIdentityItem> reportUserIdentityScanDynamoDataStore;
    private final VerifiableCredentialService verifiableCredentialService;
    private final EvcsClient evcsClient;

    public BulkMigrateVcsHandler(
            ScanDynamoDataStore<ReportUserIdentityItem> reportUserIdentityScanDynamoDataStore,
            VerifiableCredentialService verifiableCredentialService,
            EvcsClient evcsClient) {
        this.reportUserIdentityScanDynamoDataStore = reportUserIdentityScanDynamoDataStore;
        this.verifiableCredentialService = verifiableCredentialService;
        this.evcsClient = evcsClient;
    }

    @ExcludeFromGeneratedCoverageReport
    public BulkMigrateVcsHandler() {
        var configService = ConfigService.create();
        this.reportUserIdentityScanDynamoDataStore =
                new ScanDynamoDataStore<>(
                        configService.getEnvironmentVariable(
                                EnvironmentVariable.REPORT_USER_IDENTITY_TABLE_NAME),
                        ReportUserIdentityItem.class,
                        DynamoDataStore.getClient(),
                        configService);
        this.verifiableCredentialService = new VerifiableCredentialService(configService);
        this.evcsClient = new EvcsClient(configService);
    }

    @Override
    @Logging(clearState = true)
    public Report handleRequest(Request request, Context context) {
        var report = new Report();

        var previousPageLastEvaluatedHashUserId = request.reportStoreLastEvaluatedHashUserId();
        var exclusiveStartKey =
                previousPageLastEvaluatedHashUserId == null
                        ? null
                        : Map.of(
                                HASH_USER_ID,
                                AttributeValue.builder()
                                        .s(previousPageLastEvaluatedHashUserId)
                                        .build());
        LOGGER.info(
                LogHelper.buildLogMessage(
                        String.format(
                                "Starting bulk migration with exclusiveStartKey: %s",
                                exclusiveStartKey)));
        int parallelism =
                request.parallelism() == null ? DEFAULT_PARALLELISM : request.parallelism();
        var forkJoinPool = new ForkJoinPool(parallelism);

        LOGGER.info(LogHelper.buildLogMessage(String.format("Parallelism: %d", parallelism)));

        try {
            for (var page :
                    reportUserIdentityScanDynamoDataStore.scan(
                            exclusiveStartKey,
                            request.batchSize(),
                            HASH_USER_ID,
                            USER_ID,
                            IDENTITY)) {

                // Using last evaluated from previous page for batchId to allow a batch rerun
                var batchId = getBatchId(previousPageLastEvaluatedHashUserId, page.count());

                // Updating while we still have access to the current page, ready for next loop
                previousPageLastEvaluatedHashUserId =
                        page.lastEvaluatedKey() == null
                                ? null
                                : page.lastEvaluatedKey().get(HASH_USER_ID).s();

                LOGGER.info(
                        LogHelper.buildLogMessage(String.format("Processing batch: %s", batchId)));

                var batchSummary = new BatchSummary(batchId);
                try {
                    forkJoinPool
                            .submit(
                                    () ->
                                            page.items().parallelStream()
                                                    .forEach(
                                                            reportItem ->
                                                                    migrateIdentity(
                                                                            reportItem,
                                                                            batchSummary)))
                            .get();
                } catch (InterruptedException | ExecutionException e) {
                    if (e instanceof InterruptedException) {
                        Thread.currentThread().interrupt();
                    }
                    LOGGER.error(
                            LogHelper.buildErrorMessage("Parallel execution failed", e)
                                    .with(LOG_BATCH_ID.getFieldName(), batchId));
                }

                report.addBatchSummary(batchSummary);

                if (context.getRemainingTimeInMillis() <= ONE_MINUTE_IN_MS) {
                    LOGGER.info(
                            LogHelper.buildLogMessage(
                                    "Lambda close to timeout - stopping execution"));
                    report.setLastEvaluatedHashUserId(previousPageLastEvaluatedHashUserId);
                    break;
                }

                if (previousPageLastEvaluatedHashUserId == null) {
                    LOGGER.info(LogHelper.buildLogMessage("No lastEvaluatedKey - all batches run"));
                    report.setLastEvaluatedHashUserId("Null - all batches complete");
                }
            }
        } finally {
            forkJoinPool.shutdown();
        }

        return report;
    }

    private void migrateIdentity(ReportUserIdentityItem reportItem, BatchSummary batchSummary) {
        // Skip any non P2 identities
        if (!Vot.P2.name().equals(reportItem.getIdentity())) {
            // Send skipped audit event
            LOGGER.info(
                    LogHelper.buildLogMessage("Skipping migration - not a P2 identity")
                            .with(LOG_HASH_USER_ID.getFieldName(), reportItem.getHashUserId())
                            .with(LOG_VOT.getFieldName(), reportItem.getIdentity())
                            .with(LOG_BATCH_ID.getFieldName(), batchSummary.getBatchId()));
            batchSummary.incrementSkippedNonP2();
            return;
        }

        List<VerifiableCredential> vcs;
        try {
            vcs = verifiableCredentialService.getVcs(reportItem.getUserId());
        } catch (Throwable e) {
            logError(
                    "Migration failed - error fetching VCs from tactical store",
                    reportItem,
                    e,
                    batchSummary.getBatchId());
            batchSummary.incrementFailedTacticalRead(reportItem.getHashUserId());
            return;
        }

        // Skip if no VCs to migrate
        if (vcs.isEmpty()) {
            LOGGER.info(
                    LogHelper.buildLogMessage("Skipping migration - no VCs to migrate")
                            .with(LOG_HASH_USER_ID.getFieldName(), reportItem.getHashUserId())
                            .with(LOG_BATCH_ID.getFieldName(), batchSummary.getBatchId()));
            // Send skipped audit event
            batchSummary.incrementSkippedNoVcs();
            return;
        }

        // Skip already migrated identities
        if (vcs.stream().allMatch(vc -> vc.getMigrated() != null)) {
            LOGGER.info(
                    LogHelper.buildLogMessage("Skipping migration - all VCs already migrated")
                            .with(LOG_HASH_USER_ID.getFieldName(), reportItem.getHashUserId())
                            .with(LOG_BATCH_ID.getFieldName(), batchSummary.getBatchId()));
            // Send skipped audit event
            batchSummary.incrementSkippedAlreadyMigrated();
            return;
        }

        // Skip partial migrations?
        if (vcs.stream().anyMatch(vc -> vc.getMigrated() != null)) {
            LOGGER.info(
                    LogHelper.buildLogMessage("Skipping migration - partially migrated identity")
                            .with(LOG_HASH_USER_ID.getFieldName(), reportItem.getHashUserId())
                            .with(LOG_BATCH_ID.getFieldName(), batchSummary.getBatchId()));
            // Send skipped audit event
            batchSummary.incrementSkippedPartiallyMigrated();
            return;
        }

        // Migrate identity
        var timestamp = Instant.now();
        try {
            storeVcsInEvcs(reportItem.getUserId(), vcs, batchSummary.getBatchId(), timestamp);
        } catch (Throwable e) {
            logError(
                    "Migration failed - error writing to EVCS",
                    reportItem,
                    e,
                    batchSummary.getBatchId());
            // Send failed audit event
            batchSummary.incrementFailedEvcsWrite(reportItem.getHashUserId());
            return;
        }

        try {
            setMigratedOnTacticalStoreVcs(vcs, timestamp);
            LOGGER.info(
                    LogHelper.buildLogMessage("Migrated")
                            .with(LOG_HASH_USER_ID.getFieldName(), reportItem.getHashUserId())
                            .with(LOG_BATCH_ID.getFieldName(), batchSummary.getBatchId()));
            // Send migrated audit event
            batchSummary.incrementMigrated();
        } catch (Throwable e) {
            logError(
                    "Migration failed - error writing to tactical",
                    reportItem,
                    e,
                    batchSummary.getBatchId());
            // Send failed audit event
            batchSummary.incrementFailedTacticalWrite(reportItem.getHashUserId());
        }
    }

    private String getBatchId(String lastEvaluatedKey, int pageSize) {
        // The last evaluated key with the number of items in the page - should be enough to
        // process the same batch in future
        return String.format(
                "%s:%d", lastEvaluatedKey == null ? "START" : lastEvaluatedKey, pageSize);
    }

    private void storeVcsInEvcs(
            String userId, List<VerifiableCredential> vcs, String batchId, Instant timestamp)
            throws EvcsServiceException {
        evcsClient.storeUserVCs(
                userId,
                vcs.stream()
                        .map(
                                vc ->
                                        new EvcsCreateUserVCsDto(
                                                vc.getVcString(),
                                                CURRENT,
                                                new EvcsMetadata(batchId, timestamp.toString()),
                                                MIGRATED))
                        .toList());
    }

    private void setMigratedOnTacticalStoreVcs(List<VerifiableCredential> vcs, Instant timestamp)
            throws VerifiableCredentialException {
        verifiableCredentialService.updateIdentity(
                vcs.stream()
                        .map(
                                vc -> {
                                    vc.setMigrated(timestamp);
                                    return vc;
                                })
                        .toList());
    }

    private void logError(
            String message, ReportUserIdentityItem reportItem, Throwable error, String batchId) {
        LOGGER.error(
                LogHelper.buildLogMessage(message)
                        .with(LOG_ERROR_DESCRIPTION.getFieldName(), error.getMessage())
                        .with(LOG_HASH_USER_ID.getFieldName(), reportItem.getHashUserId())
                        .with(LOG_BATCH_ID.getFieldName(), batchId));
    }
}
