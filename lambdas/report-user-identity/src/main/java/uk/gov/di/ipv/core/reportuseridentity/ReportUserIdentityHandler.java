package uk.gov.di.ipv.core.reportuseridentity;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestStreamHandler;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.lambda.powertools.logging.Logging;
import software.amazon.lambda.powertools.tracing.Tracing;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.config.EnvironmentVariable;
import uk.gov.di.ipv.core.library.enums.Vot;
import uk.gov.di.ipv.core.library.exceptions.BatchDeleteException;
import uk.gov.di.ipv.core.library.exceptions.CredentialParseException;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.persistence.DynamoDataStore;
import uk.gov.di.ipv.core.library.persistence.item.VcStoreItem;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.UserIdentityService;
import uk.gov.di.ipv.core.library.verifiablecredential.service.VerifiableCredentialService;
import uk.gov.di.ipv.core.reportuseridentity.domain.ReportProcessingRequest;
import uk.gov.di.ipv.core.reportuseridentity.domain.ReportProcessingResult;
import uk.gov.di.ipv.core.reportuseridentity.domain.ReportSummary;
import uk.gov.di.ipv.core.reportuseridentity.exceptions.StopBeforeLambdaTimeoutException;
import uk.gov.di.ipv.core.reportuseridentity.persistence.ScanDynamoDataStore;
import uk.gov.di.ipv.core.reportuseridentity.persistence.item.ReportSummaryItem;
import uk.gov.di.ipv.core.reportuseridentity.persistence.item.ReportUserIdentityItem;
import uk.gov.di.ipv.core.reportuseridentity.service.ReportUserIdentityService;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.List;

@ExcludeFromGeneratedCoverageReport
public class ReportUserIdentityHandler implements RequestStreamHandler {
    public static final int STOP_TIME_IN_MILLISECONDS_BEFORE_LAMBDA_TIMEOUT = 1000;
    public static final String ATTR_NAME_USER_ID = "userId";
    private static final Logger LOGGER = LogManager.getLogger();
    private final ObjectMapper objectMapper;
    private final ConfigService configService;
    private final UserIdentityService userIdentityService;
    private final VerifiableCredentialService verifiableCredentialService;
    private final ReportUserIdentityService reportUserIdentityService;
    private final ScanDynamoDataStore<VcStoreItem> vcStoreItemScanDynamoDataStore;
    private final ScanDynamoDataStore<ReportUserIdentityItem> reportUserIdentityScanDynamoDataStore;
    private final ScanDynamoDataStore<ReportSummaryItem> reportSummaryScanDynamoDataStore;

    @SuppressWarnings({"java:S107"}) // Used by AWS
    public ReportUserIdentityHandler(
            ObjectMapper objectMapper,
            ConfigService configService,
            UserIdentityService userIdentityService,
            VerifiableCredentialService verifiableCredentialService,
            ReportUserIdentityService reportUserIdentityService,
            ScanDynamoDataStore<VcStoreItem> vcStoreItemScanDynamoDataStore,
            ScanDynamoDataStore<ReportUserIdentityItem> reportUserIdentityScanDynamoDataStore,
            ScanDynamoDataStore<ReportSummaryItem> reportSummaryScanDynamoDataStore) {
        this.objectMapper = objectMapper;
        this.configService = configService;
        this.userIdentityService = userIdentityService;
        this.verifiableCredentialService = verifiableCredentialService;
        this.reportUserIdentityService = reportUserIdentityService;
        this.vcStoreItemScanDynamoDataStore = vcStoreItemScanDynamoDataStore;
        this.reportUserIdentityScanDynamoDataStore = reportUserIdentityScanDynamoDataStore;
        this.reportSummaryScanDynamoDataStore = reportSummaryScanDynamoDataStore;
    }

    @SuppressWarnings({"unused", "java:S107"}) // Used by AWS
    public ReportUserIdentityHandler() {
        this.objectMapper = new ObjectMapper();
        this.configService = ConfigService.create();
        this.userIdentityService = new UserIdentityService(configService);
        this.verifiableCredentialService = new VerifiableCredentialService(configService);
        this.reportUserIdentityService = new ReportUserIdentityService();
        this.vcStoreItemScanDynamoDataStore =
                new ScanDynamoDataStore<>(
                        configService.getEnvironmentVariable(
                                EnvironmentVariable.USER_ISSUED_CREDENTIALS_TABLE_NAME),
                        VcStoreItem.class,
                        DynamoDataStore.getClient(),
                        configService);
        this.reportUserIdentityScanDynamoDataStore =
                new ScanDynamoDataStore<>(
                        configService.getEnvironmentVariable(
                                EnvironmentVariable.REPORT_USER_IDENTITY_TABLE_NAME),
                        ReportUserIdentityItem.class,
                        DynamoDataStore.getClient(),
                        configService);
        this.reportSummaryScanDynamoDataStore =
                new ScanDynamoDataStore<>(
                        configService.getEnvironmentVariable(
                                EnvironmentVariable.REPORT_SUMMARY_TABLE_NAME),
                        ReportSummaryItem.class,
                        DynamoDataStore.getClient(),
                        configService);
    }

    @Override
    @Tracing
    @Logging(clearState = true)
    public void handleRequest(InputStream inputStream, OutputStream outputStream, Context context)
            throws IOException {
        LogHelper.attachComponentId(configService);
        LOGGER.info(LogHelper.buildLogMessage("Start processing report."));

        ReportProcessingResult.ReportProcessingResultBuilder reportProcessingResult =
                ReportProcessingResult.builder();
        try {
            ReportProcessingRequest reportProcessingRequest =
                    objectMapper.readValue(inputStream, ReportProcessingRequest.class);
            LOGGER.info(
                    LogHelper.buildLogMessage(
                            "Request received- " + reportProcessingRequest.toString()));
            // Step-1
            scanToExtractUniqueUserIdFromTacticalStore(
                    reportProcessingResult, reportProcessingRequest, context);
            // Step-2
            processUsersToFindLOCAndUpdateDb(
                    reportProcessingRequest, reportProcessingResult, context);
            // Step-3
            reportProcessingResult = buildReportProcessingResult(reportProcessingResult);

            LOGGER.info(
                    LogHelper.buildLogMessage(
                            "Completed report processing for user's identities."));
        } catch (HttpResponseExceptionWithErrorBody | CredentialParseException e) {
            LOGGER.error(
                    LogHelper.buildErrorMessage(
                            "Stopped report processing of user's identities.", e));
        } catch (BatchDeleteException e) {
            LOGGER.info(LogHelper.buildLogMessage("Error occurred during batch write process."));
        } catch (StopBeforeLambdaTimeoutException e) {
            LOGGER.error(LogHelper.buildErrorMessage("Stopping as lambda about to timeout.", e));
        } finally {
            LOGGER.info(LogHelper.buildLogMessage("Writing output with result summary."));
            objectMapper.enable(SerializationFeature.INDENT_OUTPUT);
            objectMapper.writeValue(outputStream, reportProcessingResult.build());
        }
    }

    private void scanToExtractUniqueUserIdFromTacticalStore(
            ReportProcessingResult.ReportProcessingResultBuilder reportProcessingResult,
            ReportProcessingRequest reportProcessingRequest,
            Context context)
            throws BatchDeleteException, StopBeforeLambdaTimeoutException {
        if (reportProcessingRequest.continueUniqueUserScan()) {
            LOGGER.info(
                    LogHelper.buildLogMessage("Retrieving userIds from tactical store db table."));

            for (var page :
                    vcStoreItemScanDynamoDataStore.getItems(
                            reportProcessingRequest.tacticalStoreLastEvaluatedKey(),
                            ATTR_NAME_USER_ID)) {

                reportUserIdentityScanDynamoDataStore.createOrUpdate(
                        page.items().stream()
                                .map(VcStoreItem::getUserId)
                                .distinct()
                                .map(
                                        usrId ->
                                                new ReportUserIdentityItem(
                                                        usrId, null, null, null, null))
                                .toList());

                reportProcessingResult.tacticalStoreLastEvaluatedKey(page.lastEvaluatedKey());

                checkLambdaRemainingExecutionTime(context);
            }
            LOGGER.info(
                    LogHelper.buildLogMessage(
                            "Tactical storage scan completed to get unique users."));
            reportProcessingResult.tacticalStoreLastEvaluatedKey(null);
        }
    }

    private void processUsersToFindLOCAndUpdateDb(
            ReportProcessingRequest reportProcessingRequest,
            ReportProcessingResult.ReportProcessingResultBuilder reportProcessingResult,
            Context context)
            throws CredentialParseException, HttpResponseExceptionWithErrorBody,
                    BatchDeleteException, StopBeforeLambdaTimeoutException {
        if (reportProcessingRequest.continueUserIdentityScan()) {
            LOGGER.info(
                    LogHelper.buildLogMessage(
                            "Processing unique users to update their aggregate identities."));

            List<ReportUserIdentityItem> totalReportUserIdentityItems = new ArrayList<>();
            for (var page :
                    reportUserIdentityScanDynamoDataStore.getItems(
                            reportProcessingRequest.userIdentitylastEvaluatedKey(),
                            ATTR_NAME_USER_ID,
                            "identity",
                            "migrated")) {
                var userIds = page.items().stream().map(ReportUserIdentityItem::getUserId).toList();
                LOGGER.info(
                        LogHelper.buildLogMessage(
                                String.format(
                                        "Checking user identity for total (%s) users.",
                                        userIds.size())));
                List<ReportUserIdentityItem> reportUserIdentityItems = new ArrayList<>();
                for (String userId : userIds) {
                    reportUserIdentityItems.add(evaluateUserIdentityDetail(userId));
                }
                LOGGER.info(
                        LogHelper.buildLogMessage(
                                "Updating processed user's identity.-"
                                        + reportUserIdentityItems.size()));
                reportUserIdentityScanDynamoDataStore.createOrUpdate(reportUserIdentityItems);

                aggregateAndPersistIdentities(reportUserIdentityItems);

                totalReportUserIdentityItems.addAll(reportUserIdentityItems);
                reportProcessingResult.userIdentitylastEvaluatedKey(page.lastEvaluatedKey());

                try {
                    checkLambdaRemainingExecutionTime(context);
                } catch (StopBeforeLambdaTimeoutException e) {
                    reportProcessingResult.users(totalReportUserIdentityItems);
                    throw e;
                }
            }
            LOGGER.info(LogHelper.buildLogMessage("User identity check scan completed."));
            reportProcessingResult.userIdentitylastEvaluatedKey(null);
            reportProcessingResult.users(totalReportUserIdentityItems);
        }
    }

    private ReportUserIdentityItem evaluateUserIdentityDetail(String userId)
            throws CredentialParseException, HttpResponseExceptionWithErrorBody {
        var tacticalVcs = verifiableCredentialService.getVcs(userId);
        if (!userIdentityService.areVcsCorrelated(tacticalVcs)) {
            LOGGER.info(
                    LogHelper.buildLogMessage(
                            String.format(
                                    "User (%s) VCs not correlated.",
                                    ReportUserIdentityItem.getUserHash(userId))));
            return new ReportUserIdentityItem(
                    userId,
                    Vot.P0.name(),
                    tacticalVcs.size(),
                    reportUserIdentityService.getIdentityConstituent(tacticalVcs),
                    false);
        } else {
            boolean anyVCsMigrated = tacticalVcs.stream().anyMatch(vc -> vc.getMigrated() != null);
            boolean allVCsMigrated = tacticalVcs.stream().allMatch(vc -> vc.getMigrated() != null);

            if (anyVCsMigrated && !allVCsMigrated) {
                LOGGER.warn(
                        LogHelper.buildLogMessage(
                                String.format(
                                        "Not all VCs are migrated for this user (%s).",
                                        ReportUserIdentityItem.getUserHash(userId))));
            }

            return new ReportUserIdentityItem(
                    userId,
                    reportUserIdentityService
                            .getStrongestAttainedVotForCredentials(tacticalVcs)
                            .orElse(Vot.P0)
                            .name(),
                    tacticalVcs.size(),
                    reportUserIdentityService.getIdentityConstituent(tacticalVcs),
                    allVCsMigrated);
        }
    }

    private void aggregateAndPersistIdentities(List<ReportUserIdentityItem> items) {
        LOGGER.info(LogHelper.buildLogMessage("Updating aggregate identities values."));
        var reportSummaryItem =
                reportSummaryScanDynamoDataStore.getItem(ScanDynamoDataStore.KEY_VALUE);
        if (reportSummaryItem == null) {
            reportSummaryItem =
                    new ReportSummaryItem(ScanDynamoDataStore.KEY_VALUE, 0L, 0L, 0L, 0L);
        }
        List<ReportUserIdentityItem> totalP2Identities =
                items.stream().filter(ui -> Vot.P2.name().equals(ui.getIdentity())).toList();
        reportSummaryItem.setTotalP2(reportSummaryItem.getTotalP2() + totalP2Identities.size());
        reportSummaryItem.setTotalP2Migrated(
                reportSummaryItem.getTotalP2Migrated()
                        + totalP2Identities.stream()
                                .filter(item -> (Boolean.TRUE.equals(item.getMigrated())))
                                .count());
        reportSummaryItem.setTotalP1(
                reportSummaryItem.getTotalP1()
                        + items.stream()
                                .filter(ui -> Vot.P1.name().equals(ui.getIdentity()))
                                .count());
        reportSummaryItem.setTotalP0(
                reportSummaryItem.getTotalP0()
                        + items.stream()
                                .filter(ui -> Vot.P0.name().equals(ui.getIdentity()))
                                .count());
        reportSummaryScanDynamoDataStore.update(reportSummaryItem);
    }

    private ReportProcessingResult.ReportProcessingResultBuilder buildReportProcessingResult(
            ReportProcessingResult.ReportProcessingResultBuilder reportProcessingResult) {
        LOGGER.info(LogHelper.buildLogMessage("Building report processing summary result."));
        var reportSummaryItem =
                reportSummaryScanDynamoDataStore.getItem(ScanDynamoDataStore.KEY_VALUE);
        if (reportSummaryItem == null) {
            reportSummaryItem =
                    new ReportSummaryItem(ScanDynamoDataStore.KEY_VALUE, 0L, 0L, 0L, 0L);
        }
        return reportProcessingResult.summary(
                new ReportSummary(
                        reportSummaryItem.getTotalP2(),
                        reportSummaryItem.getTotalP2Migrated(),
                        reportSummaryItem.getTotalP1(),
                        reportSummaryItem.getTotalP0()));
    }

    private void checkLambdaRemainingExecutionTime(Context context)
            throws StopBeforeLambdaTimeoutException {
        if (context.getRemainingTimeInMillis() < STOP_TIME_IN_MILLISECONDS_BEFORE_LAMBDA_TIMEOUT) {
            throw new StopBeforeLambdaTimeoutException("Stopping as lambda about to timeout.");
        }
    }
}
