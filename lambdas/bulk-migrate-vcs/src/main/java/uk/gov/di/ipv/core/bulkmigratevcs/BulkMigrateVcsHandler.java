package uk.gov.di.ipv.core.bulkmigratevcs;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.message.StringMapMessage;
import software.amazon.awssdk.enhanced.dynamodb.model.Page;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.lambda.powertools.logging.Logging;
import uk.gov.di.ipv.core.bulkmigratevcs.domain.BatchReport;
import uk.gov.di.ipv.core.bulkmigratevcs.domain.PageSummary;
import uk.gov.di.ipv.core.bulkmigratevcs.domain.Request;
import uk.gov.di.ipv.core.bulkmigratevcs.exceptions.TooManyBatchIdsException;
import uk.gov.di.ipv.core.bulkmigratevcs.factories.EvcsClientFactory;
import uk.gov.di.ipv.core.bulkmigratevcs.factories.ForkJoinPoolFactory;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.auditing.AuditEvent;
import uk.gov.di.ipv.core.library.auditing.AuditEventTypes;
import uk.gov.di.ipv.core.library.auditing.AuditEventUser;
import uk.gov.di.ipv.core.library.auditing.extension.AuditExtensions;
import uk.gov.di.ipv.core.library.auditing.extension.AuditExtensionsEvcsFailedMigration;
import uk.gov.di.ipv.core.library.auditing.extension.AuditExtensionsEvcsSkippedMigration;
import uk.gov.di.ipv.core.library.auditing.extension.AuditExtensionsEvcsSuccessfulMigration;
import uk.gov.di.ipv.core.library.client.EvcsClient;
import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
import uk.gov.di.ipv.core.library.config.EnvironmentVariable;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.dto.EvcsCreateUserVCsDto;
import uk.gov.di.ipv.core.library.enums.Vot;
import uk.gov.di.ipv.core.library.exception.AuditException;
import uk.gov.di.ipv.core.library.exception.EvcsServiceException;
import uk.gov.di.ipv.core.library.exceptions.VerifiableCredentialException;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.metadata.MigrationMetadata;
import uk.gov.di.ipv.core.library.metadata.MigrationMetadataBatchDetails;
import uk.gov.di.ipv.core.library.persistence.DynamoDataStore;
import uk.gov.di.ipv.core.library.persistence.ScanDynamoDataStore;
import uk.gov.di.ipv.core.library.persistence.item.ReportUserIdentityItem;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.verifiablecredential.service.VerifiableCredentialService;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ForkJoinPool;

import static uk.gov.di.ipv.core.library.auditing.AuditEventTypes.IPV_EVCS_MIGRATION_FAILURE;
import static uk.gov.di.ipv.core.library.auditing.AuditEventTypes.IPV_EVCS_MIGRATION_SKIPPED;
import static uk.gov.di.ipv.core.library.auditing.AuditEventTypes.IPV_EVCS_MIGRATION_SUCCESS;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.BULK_MIGRATION_ROLLBACK_BATCHES;
import static uk.gov.di.ipv.core.library.enums.EvcsVCState.CURRENT;
import static uk.gov.di.ipv.core.library.enums.EvcsVcProvenance.MIGRATED;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_BATCH_ID;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_ERROR_DESCRIPTION;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_ERROR_STACK;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_HASH_USER_ID;

public class BulkMigrateVcsHandler implements RequestHandler<Request, BatchReport> {
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final Logger LOGGER = LogManager.getLogger();
    private static final String HASH_USER_ID = "hashUserId";
    private static final String USER_ID = "userId";
    private static final String IDENTITY = "identity";
    private static final int DEFAULT_PARALLELISM = 4;
    private static final int ONE_MINUTE_IN_MS = 60_000;
    private static final String PAGE_ITEM_COUNT = "pageItemCount";
    private static final String PAGE_EXCLUSIVE_START_KEY = "pageExclusiveStartKey";
    private static final int EVCS_CLIENT_GOAWAY_LIMIT = 9_000;
    private static final String REPORT = "report";
    private final ScanDynamoDataStore<ReportUserIdentityItem> reportUserIdentityScanDynamoDataStore;
    private final VerifiableCredentialService verifiableCredentialService;
    private final ForkJoinPoolFactory forkJoinPoolFactory;
    private final EvcsClientFactory evcsClientFactory;
    private final ConfigService configService;
    private final AuditService auditService;
    private EvcsClient evcsClient;

    public BulkMigrateVcsHandler(
            ScanDynamoDataStore<ReportUserIdentityItem> reportUserIdentityScanDynamoDataStore,
            VerifiableCredentialService verifiableCredentialService,
            EvcsClientFactory evcsClientFactory,
            ForkJoinPoolFactory forkJoinPoolFactory,
            ConfigService configService,
            AuditService auditService) {
        this.reportUserIdentityScanDynamoDataStore = reportUserIdentityScanDynamoDataStore;
        this.verifiableCredentialService = verifiableCredentialService;
        this.evcsClientFactory = evcsClientFactory;
        this.forkJoinPoolFactory = forkJoinPoolFactory;
        this.configService = configService;
        this.auditService = auditService;
    }

    @ExcludeFromGeneratedCoverageReport
    public BulkMigrateVcsHandler() {
        this.configService = ConfigService.create();
        this.auditService = AuditService.create(configService);
        this.reportUserIdentityScanDynamoDataStore =
                new ScanDynamoDataStore<>(
                        configService.getEnvironmentVariable(
                                EnvironmentVariable.REPORT_USER_IDENTITY_TABLE_NAME),
                        ReportUserIdentityItem.class,
                        DynamoDataStore.getClient(),
                        configService);
        this.verifiableCredentialService = new VerifiableCredentialService(configService);
        this.evcsClientFactory = new EvcsClientFactory(configService);
        this.forkJoinPoolFactory = new ForkJoinPoolFactory();
    }

    @Override
    @Logging(clearState = true)
    public BatchReport handleRequest(Request request, Context context) {
        var batchId = request.batch().id();
        var report = new BatchReport(batchId);
        var previousPageLastEvaluatedHashUserId = request.batch().exclusiveStartHashUserId();
        var exclusiveStartKey =
                previousPageLastEvaluatedHashUserId == null
                        ? null
                        : Map.of(
                                HASH_USER_ID,
                                AttributeValue.builder()
                                        .s(previousPageLastEvaluatedHashUserId)
                                        .build());
        var forkJoinPool =
                forkJoinPoolFactory.getForkJoinPool(
                        request.parallelism() == null
                                ? DEFAULT_PARALLELISM
                                : request.parallelism());

        LOGGER.info(
                LogHelper.buildLogMessage("Starting bulk migration")
                        .with(LOG_BATCH_ID.getFieldName(), batchId)
                        .with("batchSize", request.batch().size())
                        .with("parallelism", forkJoinPool.getParallelism())
                        .with("exclusiveStartKey", exclusiveStartKey));

        evcsClient = evcsClientFactory.getClient();
        var evcsClientCount = 1;

        try {
            for (var page :
                    reportUserIdentityScanDynamoDataStore.scan(
                            exclusiveStartKey,
                            request.pageSize(),
                            HASH_USER_ID,
                            USER_ID,
                            IDENTITY)) {

                int maxMigratedByEndOfPage = report.getTotalMigrated() + page.count();
                if (maxMigratedByEndOfPage / EVCS_CLIENT_GOAWAY_LIMIT == evcsClientCount) {
                    // API gateway seems to have a limit on the number of requests from one
                    // connection
                    LOGGER.info(
                            LogHelper.buildLogMessage(
                                            "Approaching EVCS client GOAWAY limit, refreshing client")
                                    .with("evcsClientCount", evcsClientCount)
                                    .with("maxMigratedByEndOfPage", maxMigratedByEndOfPage));
                    evcsClient = evcsClientFactory.getClient();
                    evcsClientCount++;
                }

                var pageSummary =
                        new PageSummary(previousPageLastEvaluatedHashUserId, page.count());

                LOGGER.info(
                        LogHelper.buildLogMessage("Processing page")
                                .with(PAGE_EXCLUSIVE_START_KEY, pageSummary.getExclusiveStartKey())
                                .with(PAGE_ITEM_COUNT, pageSummary.getCount())
                                .with("pageCount", report.getPageSummaries().size() + 1));

                // Updating for next loop while we still have access to the page
                previousPageLastEvaluatedHashUserId = getPageLastEvaluatedHashUserId(page);

                submitPageToThreadPool(forkJoinPool, page, pageSummary, batchId);

                report.addPageSummary(pageSummary);

                var remainingMillis = context.getRemainingTimeInMillis();
                LOGGER.info(
                        LogHelper.buildLogMessage("Remaining time in millis")
                                .with("remaining", remainingMillis));
                if (remainingMillis <= ONE_MINUTE_IN_MS) {
                    LOGGER.warn(
                            LogHelper.buildLogMessage(
                                            "Lambda close to timeout - stopping execution")
                                    .with(LOG_BATCH_ID.getFieldName(), batchId)
                                    .with(
                                            PAGE_EXCLUSIVE_START_KEY,
                                            pageSummary.getExclusiveStartKey())
                                    .with(PAGE_ITEM_COUNT, pageSummary.getCount()));
                    report.setExitReason("Lambda close to timeout");
                    report.setNextBatchExclusiveStartKey(getPageLastEvaluatedHashUserId(page));
                    return report;
                }

                if (report.getTotalEvaluated() >= request.batch().size()) {
                    LOGGER.info(
                            LogHelper.buildLogMessage("All items in batch processed")
                                    .with(LOG_BATCH_ID.getFieldName(), batchId)
                                    .with(
                                            PAGE_EXCLUSIVE_START_KEY,
                                            pageSummary.getExclusiveStartKey())
                                    .with(PAGE_ITEM_COUNT, pageSummary.getCount()));
                    report.setExitReason("All items in batch processed");
                    report.setNextBatchExclusiveStartKey(getPageLastEvaluatedHashUserId(page));
                    return report;
                }

                if (page.lastEvaluatedKey() == null) {
                    LOGGER.info(
                            LogHelper.buildLogMessage("No lastEvaluatedKey - all pages run")
                                    .with(LOG_BATCH_ID.getFieldName(), batchId)
                                    .with(PAGE_ITEM_COUNT, pageSummary.getCount()));
                    report.setExitReason("Scan complete");
                    report.setNextBatchExclusiveStartKey(getPageLastEvaluatedHashUserId(page));
                }
            }
        } finally {
            logReport(report);
            try {
                auditService.awaitAuditEvents();
            } catch (AuditException e) {
                LOGGER.error(
                        LogHelper.buildLogMessage(
                                "Error awaiting audit events - returning report"));
            }
            forkJoinPool.shutdown();
        }

        return report;
    }

    private void submitPageToThreadPool(
            ForkJoinPool forkJoinPool,
            Page<ReportUserIdentityItem> page,
            PageSummary pageSummary,
            String batchId) {
        try {
            forkJoinPool
                    .submit(
                            () ->
                                    page.items().parallelStream()
                                            .forEach(
                                                    reportItem ->
                                                            migrateIdentity(
                                                                    reportItem,
                                                                    pageSummary,
                                                                    batchId)))
                    .get();
        } catch (InterruptedException | ExecutionException e) {
            if (e instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            LOGGER.error(
                    LogHelper.buildErrorMessage("Parallel execution failed", e)
                            .with(LOG_ERROR_STACK.getFieldName(), e.getStackTrace())
                            .with(LOG_BATCH_ID.getFieldName(), batchId)
                            .with(PAGE_EXCLUSIVE_START_KEY, pageSummary.getExclusiveStartKey())
                            .with(PAGE_ITEM_COUNT, pageSummary.getCount()));
        }
    }

    private void migrateIdentity(
            ReportUserIdentityItem reportItem, PageSummary pageSummary, String batchId) {
        var userId = reportItem.getUserId();
        // Skip any non P2 identities
        if (!Vot.P2.name().equals(reportItem.getIdentity())) {
            LOGGER.info(
                    annotateLog(
                            "Skipping migration - not a P2 identity",
                            reportItem,
                            batchId,
                            pageSummary));
            sendSkippedAuditEvent(userId, batchId, "not_p2_identity");
            pageSummary.incrementSkippedNonP2();
            return;
        }

        List<VerifiableCredential> vcs;
        try {
            vcs = verifiableCredentialService.getVcs(reportItem.getUserId());
        } catch (Exception e) {
            logError(
                    "Migration failed - error fetching VCs from tactical store",
                    reportItem,
                    e,
                    batchId,
                    pageSummary);
            sendFailureAuditEvent(
                    userId, batchId, List.of(), "Failed to fetch VCs from tactical store");
            pageSummary.incrementFailedTacticalRead(reportItem.getHashUserId());
            return;
        }

        // Skip if no VCs to migrate
        if (vcs.isEmpty()) {
            LOGGER.info(
                    annotateLog(
                            "Skipping migration - no VCs to migrate",
                            reportItem,
                            batchId,
                            pageSummary));
            sendSkippedAuditEvent(userId, batchId, "missing_credentials");
            pageSummary.incrementSkippedNoVcs();
            return;
        }

        boolean vcsAreFromRollbackBatch;
        try {
            vcsAreFromRollbackBatch =
                    vcsAreFromRollbackBatch(vcs, reportItem, batchId, pageSummary);
        } catch (TooManyBatchIdsException e) {
            logError(
                    "Migration failed - too many batch IDs found in credentials",
                    reportItem,
                    e,
                    batchId,
                    pageSummary);
            sendFailureAuditEvent(userId, batchId, vcs, "Too many batch IDs in tactical VCs");
            pageSummary.incrementFailedTooManyBatchIds(reportItem.getHashUserId());
            return;
        }

        // Skip already migrated identities
        if (vcs.stream().allMatch(vc -> vc.getMigrated() != null) && !vcsAreFromRollbackBatch) {
            LOGGER.info(
                    annotateLog(
                            "Skipping migration - all VCs already migrated",
                            reportItem,
                            batchId,
                            pageSummary));
            sendSkippedAuditEvent(userId, batchId, "already_migrated");
            pageSummary.incrementSkippedAlreadyMigrated();
            return;
        }

        // Skip partial migrations
        if (vcs.stream().anyMatch(vc -> vc.getMigrated() != null) && !vcsAreFromRollbackBatch) {
            LOGGER.info(
                    annotateLog(
                            "Skipping migration - partially migrated identity",
                            reportItem,
                            batchId,
                            pageSummary));
            sendSkippedAuditEvent(userId, batchId, "partially_migrated");
            pageSummary.incrementSkippedPartiallyMigrated();
            return;
        }

        // Migrate identity
        var timestamp = Instant.now();
        try {
            storeVcsInEvcs(reportItem.getUserId(), vcs, batchId, timestamp);
            pageSummary.incrementMigratedVcs(vcs.size());
        } catch (Exception e) {
            logError(
                    "Migration failed - error writing to EVCS",
                    reportItem,
                    e,
                    batchId,
                    pageSummary);
            sendFailureAuditEvent(userId, batchId, vcs, "Failed to write VCs to the EVCS");
            pageSummary.incrementFailedEvcsWrite(reportItem.getHashUserId());
            return;
        }

        try {
            setMigratedOnTacticalStoreVcs(vcs, timestamp, batchId);
            LOGGER.info(annotateLog("Migrated", reportItem, batchId, pageSummary));
            sendSuccessAuditEvent(userId, batchId, vcs);
            pageSummary.incrementMigrated();
        } catch (Exception e) {
            logError(
                    "Migration failed - error writing to tactical",
                    reportItem,
                    e,
                    batchId,
                    pageSummary);
            sendFailureAuditEvent(userId, batchId, vcs, "Failed to write VCs to tactical store");
            pageSummary.incrementFailedTacticalWrite(reportItem.getHashUserId());
        }
    }

    private boolean vcsAreFromRollbackBatch(
            List<VerifiableCredential> vcs,
            ReportUserIdentityItem reportItem,
            String batchId,
            PageSummary pageSummary)
            throws TooManyBatchIdsException {
        var batchIds = vcs.stream().map(VerifiableCredential::getBatchId).distinct().toList();
        if (batchIds.isEmpty()) {
            return false;
        }
        if (batchIds.size() > 1) {
            // This is an unexpected case
            LOGGER.error(
                    annotateLog(
                                    "Inconsistent batch IDs in identity VCs",
                                    reportItem,
                                    batchId,
                                    pageSummary)
                            .with("vcBatchIds", batchIds)
                            .with("vcCount", vcs.size()));
            throw new TooManyBatchIdsException("Inconsistent batch IDs in identity VCs");
        }
        if (!configService
                .getStringListParameter(BULK_MIGRATION_ROLLBACK_BATCHES)
                .contains(batchIds.get(0))) {
            return false;
        }
        LOGGER.info(
                annotateLog(
                                "Previously migrated identity in rollback batch",
                                reportItem,
                                batchId,
                                pageSummary)
                        .with("rollbackBatchId", batchIds.get(0)));
        return true;
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
                                                new MigrationMetadata(
                                                        new MigrationMetadataBatchDetails(
                                                                batchId, timestamp.toString())),
                                                MIGRATED))
                        .toList());
    }

    private void setMigratedOnTacticalStoreVcs(
            List<VerifiableCredential> vcs, Instant timestamp, String batchId)
            throws VerifiableCredentialException {
        vcs.forEach(
                vc -> {
                    vc.setMigrated(timestamp);
                    vc.setBatchId(batchId);
                });
        verifiableCredentialService.updateIdentity(vcs);
    }

    private void logError(
            String message,
            ReportUserIdentityItem reportItem,
            Throwable error,
            String batchId,
            PageSummary pageSummary) {

        LOGGER.error(
                annotateLog(message, reportItem, batchId, pageSummary)
                        .with(LOG_ERROR_DESCRIPTION.getFieldName(), error.getMessage())
                        .with(LOG_ERROR_STACK.getFieldName(), error.getStackTrace()));
    }

    private StringMapMessage annotateLog(
            String message,
            ReportUserIdentityItem reportItem,
            String batchId,
            PageSummary pageSummary) {
        return LogHelper.buildLogMessage(message)
                .with(LOG_HASH_USER_ID.getFieldName(), reportItem.getHashUserId())
                .with(LOG_BATCH_ID.getFieldName(), batchId)
                .with(PAGE_EXCLUSIVE_START_KEY, pageSummary.getExclusiveStartKey())
                .with(PAGE_ITEM_COUNT, pageSummary.getCount());
    }

    private String getPageLastEvaluatedHashUserId(Page<ReportUserIdentityItem> page) {
        return page.lastEvaluatedKey() == null
                ? "null"
                : page.lastEvaluatedKey().get(HASH_USER_ID).s();
    }

    private List<String> getVcSignatures(List<VerifiableCredential> vcs) {
        return vcs.stream().map(vc -> vc.getVcString().split("\\.")[2]).toList();
    }

    private void sendSuccessAuditEvent(
            String userId, String batchId, List<VerifiableCredential> vcs) {
        sendAuditEvent(
                IPV_EVCS_MIGRATION_SUCCESS,
                userId,
                new AuditExtensionsEvcsSuccessfulMigration(
                        batchId, getVcSignatures(vcs), vcs.size()));
    }

    private void sendSkippedAuditEvent(String userId, String batchId, String reason) {
        sendAuditEvent(
                IPV_EVCS_MIGRATION_SKIPPED,
                userId,
                new AuditExtensionsEvcsSkippedMigration(batchId, reason));
    }

    private void sendFailureAuditEvent(
            String userId, String batchId, List<VerifiableCredential> vcs, String reason) {
        sendAuditEvent(
                IPV_EVCS_MIGRATION_FAILURE,
                userId,
                new AuditExtensionsEvcsFailedMigration(batchId, vcs.size(), reason));
    }

    private void sendAuditEvent(
            AuditEventTypes auditEventType, String userId, AuditExtensions extension) {
        auditService.sendAuditEvent(
                AuditEvent.createWithoutDeviceInformation(
                        auditEventType,
                        configService.getParameter(ConfigurationVariable.COMPONENT_ID),
                        new AuditEventUser(userId, "", "", ""),
                        extension));
    }

    private void logReport(BatchReport report) {
        try {
            LOGGER.info(
                    LogHelper.buildLogMessage("Returning report")
                            .with(REPORT, OBJECT_MAPPER.writeValueAsString(report)));
        } catch (JsonProcessingException e) {
            LOGGER.error(LogHelper.buildErrorMessage("Failed to log report", e));
        }
    }
}
