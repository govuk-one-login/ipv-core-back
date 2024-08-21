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
import uk.gov.di.ipv.core.library.exceptions.BatchProcessingException;
import uk.gov.di.ipv.core.library.exceptions.CredentialParseException;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.core.library.helpers.DynamoDbHelper;
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
import uk.gov.di.ipv.core.reportuseridentity.persistence.item.ReportUserIdentityItem;
import uk.gov.di.ipv.core.reportuseridentity.service.ReportUserIdentityService;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@ExcludeFromGeneratedCoverageReport
public class ReportUserIdentityHandler implements RequestStreamHandler {
    public static final int STOP_TIME_IN_MILLISECONDS_BEFORE_LAMBDA_TIMEOUT = 60000;
    public static final String ATTR_NAME_USER_ID = "userId";
    private static final Logger LOGGER = LogManager.getLogger();
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    public static final String USER_HASH = "user_hash";
    private final ConfigService configService;
    private final UserIdentityService userIdentityService;
    private final VerifiableCredentialService verifiableCredentialService;
    private final ReportUserIdentityService reportUserIdentityService;
    private final ScanDynamoDataStore<VcStoreItem> vcStoreItemScanDynamoDataStore;
    private final ScanDynamoDataStore<ReportUserIdentityItem> reportUserIdentityScanDynamoDataStore;

    @SuppressWarnings({"java:S107"}) // Used by AWS
    public ReportUserIdentityHandler(
            ConfigService configService,
            UserIdentityService userIdentityService,
            VerifiableCredentialService verifiableCredentialService,
            ReportUserIdentityService reportUserIdentityService,
            ScanDynamoDataStore<VcStoreItem> vcStoreItemScanDynamoDataStore,
            ScanDynamoDataStore<ReportUserIdentityItem> reportUserIdentityScanDynamoDataStore) {
        this.configService = configService;
        this.userIdentityService = userIdentityService;
        this.verifiableCredentialService = verifiableCredentialService;
        this.reportUserIdentityService = reportUserIdentityService;
        this.vcStoreItemScanDynamoDataStore = vcStoreItemScanDynamoDataStore;
        this.reportUserIdentityScanDynamoDataStore = reportUserIdentityScanDynamoDataStore;
    }

    @SuppressWarnings({"unused", "java:S107"}) // Used by AWS
    public ReportUserIdentityHandler() {
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
    }

    @Override
    @Tracing
    @Logging(clearState = true)
    public void handleRequest(InputStream inputStream, OutputStream outputStream, Context context)
            throws IOException {
        LogHelper.attachComponentId(configService);
        LOGGER.info(LogHelper.buildLogMessage("Start processing report."));

        var reportProcessingResult = new ReportProcessingResult();
        try {
            ReportProcessingRequest reportProcessingRequest =
                    OBJECT_MAPPER.readValue(inputStream, ReportProcessingRequest.class);

            // Step-1
            if (reportProcessingRequest.continueUniqueUserScan()) {
                scanToExtractUniqueUserIdFromTacticalStore(
                        reportProcessingRequest, reportProcessingResult, context);
            }
            // Step-2
            if (reportProcessingRequest.continueUserIdentityScan()) {
                processUsersToFindLOCAndUpdateDb(
                        reportProcessingRequest, reportProcessingResult, context);
            }
            // Step-3
            if (reportProcessingRequest.generateReport()) {
                buildReportProcessingResult(
                        reportProcessingRequest, reportProcessingResult, context);
            }

            LOGGER.info(
                    LogHelper.buildLogMessage(
                            "Completed report processing for user's identities."));
        } catch (BatchProcessingException e) {
            LOGGER.info(LogHelper.buildLogMessage("Error occurred during batch write process."));
        } catch (StopBeforeLambdaTimeoutException e) {
            LOGGER.error(LogHelper.buildErrorMessage("Stopping as lambda about to timeout.", e));
        } finally {
            LOGGER.info(LogHelper.buildLogMessage("Writing output with result summary."));
            OBJECT_MAPPER.enable(SerializationFeature.INDENT_OUTPUT);
            OBJECT_MAPPER.writeValue(outputStream, reportProcessingResult);
        }
    }

    private void scanToExtractUniqueUserIdFromTacticalStore(
            ReportProcessingRequest reportProcessingRequest,
            ReportProcessingResult reportProcessingResult,
            Context context)
            throws BatchProcessingException, StopBeforeLambdaTimeoutException {
        LOGGER.info(LogHelper.buildLogMessage("Retrieving userIds from tactical store db table."));

        for (var page :
                vcStoreItemScanDynamoDataStore.scan(
                        DynamoDbHelper.marshallToLastEvaluatedKey(
                                reportProcessingRequest.tacticalStoreLastEvaluatedKey()),
                        reportProcessingRequest.pageSize(),
                        ATTR_NAME_USER_ID)) {

            reportUserIdentityScanDynamoDataStore.createOrUpdate(
                    page.items().stream()
                            .map(VcStoreItem::getUserId)
                            .distinct()
                            .map(usrId -> new ReportUserIdentityItem(usrId, null, null, null, null))
                            .toList());

            reportProcessingResult.setTacticalStoreLastEvaluatedKey(
                    DynamoDbHelper.unmarshallLastEvaluatedKey(page.lastEvaluatedKey()));
            reportProcessingResult.addTacticalVcsEvaluated(page.items().size());

            checkLambdaRemainingExecutionTime(context);
        }
        LOGGER.info(
                LogHelper.buildLogMessage("Tactical storage scan completed to get unique users."));
        reportProcessingResult.setTacticalStoreLastEvaluatedKey(null);
    }

    private void processUsersToFindLOCAndUpdateDb(
            ReportProcessingRequest reportProcessingRequest,
            ReportProcessingResult reportProcessingResult,
            Context context)
            throws BatchProcessingException, StopBeforeLambdaTimeoutException {
        LOGGER.info(
                LogHelper.buildLogMessage(
                        "Processing unique users to update their aggregate identities."));

        for (var page :
                reportUserIdentityScanDynamoDataStore.scan(
                        DynamoDbHelper.marshallToLastEvaluatedKey(
                                reportProcessingRequest.userIdentitylastEvaluatedKey()),
                        reportProcessingRequest.pageSize(),
                        ATTR_NAME_USER_ID)) {
            var userIds = page.items().stream().map(ReportUserIdentityItem::getUserId).toList();
            LOGGER.info(
                    LogHelper.buildLogMessage(
                            String.format(
                                    "Checking user identity for total (%s) users.",
                                    userIds.size())));
            List<ReportUserIdentityItem> reportUserIdentityItems = new ArrayList<>(userIds.size());
            for (String userId : userIds) {
                ReportUserIdentityItem reportUserIdentityItem = evaluateUserIdentityDetail(userId);
                if (reportUserIdentityItem != null) {
                    reportUserIdentityItems.add(reportUserIdentityItem);
                }
            }
            LOGGER.info(
                    LogHelper.buildLogMessage(
                            "Updating processed user's identity.-"
                                    + reportUserIdentityItems.size()));
            reportUserIdentityScanDynamoDataStore.createOrUpdate(reportUserIdentityItems);

            reportProcessingResult.setUserIdentitylastEvaluatedKey(
                    DynamoDbHelper.unmarshallLastEvaluatedKey(page.lastEvaluatedKey()));
            reportProcessingResult.addUserIdentitiesEvaluated(page.items().size());

            checkLambdaRemainingExecutionTime(context);
        }
        LOGGER.info(LogHelper.buildLogMessage("User identity check scan completed."));
        reportProcessingResult.setUserIdentitylastEvaluatedKey(null);
    }

    private ReportUserIdentityItem evaluateUserIdentityDetail(String userId) {
        String userHash = ReportUserIdentityItem.getUserHash(userId);
        try {
            var tacticalVcs = verifiableCredentialService.getVcs(userId);

            if (!userIdentityService.areVcsCorrelated(tacticalVcs)) {
                LOGGER.info(
                        LogHelper.buildLogMessage("User VCs not correlated.")
                                .with(USER_HASH, userHash));
                return new ReportUserIdentityItem(
                        userId,
                        Vot.P0.name(),
                        tacticalVcs.size(),
                        reportUserIdentityService.getIdentityConstituent(tacticalVcs),
                        false);
            } else {
                boolean anyVCsMigrated =
                        tacticalVcs.stream().anyMatch(vc -> vc.getMigrated() != null);
                boolean allVCsMigrated =
                        tacticalVcs.stream().allMatch(vc -> vc.getMigrated() != null);

                if (anyVCsMigrated && !allVCsMigrated) {
                    LOGGER.warn(
                            LogHelper.buildLogMessage("Not all VCs are migrated for this user.")
                                    .with(USER_HASH, userHash));
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
        } catch (HttpResponseExceptionWithErrorBody | CredentialParseException ex) {
            LOGGER.warn(
                    LogHelper.buildErrorMessage(
                                    "Exception while retrieving user VCs or vc having missing name.",
                                    ex)
                            .with(USER_HASH, userHash));
            return null;
        }
    }

    private void buildReportProcessingResult(
            ReportProcessingRequest reportProcessingRequest,
            ReportProcessingResult reportProcessingResult,
            Context context)
            throws StopBeforeLambdaTimeoutException {
        LOGGER.info(LogHelper.buildLogMessage("Building report processing summary result."));
        long totalP2Identities = 0L;
        long totalP2IdentitiesMigrated = 0L;
        long totalP1Identities = 0L;
        long totalP0Identities = 0L;
        Map<String, Long> previousConstituteVCsTotal = Collections.emptyMap();
        Map<String, Long> mergedConstituteVCsTotal = Collections.emptyMap();
        for (var page :
                reportUserIdentityScanDynamoDataStore.scan(
                        DynamoDbHelper.marshallToLastEvaluatedKey(
                                reportProcessingRequest.buildReportLastEvaluatedKey()),
                        reportProcessingRequest.pageSize())) {
            var p2Identities =
                    page.items().stream()
                            .filter(ui -> Vot.P2.name().equals(ui.getIdentity()))
                            .toList();
            totalP2Identities = totalP2Identities + p2Identities.size();
            totalP2IdentitiesMigrated =
                    totalP2IdentitiesMigrated
                            + p2Identities.stream()
                                    .filter(item -> (Boolean.TRUE.equals(item.getMigrated())))
                                    .count();
            totalP1Identities =
                    totalP1Identities
                            + page.items().stream()
                                    .filter(ui -> Vot.P1.name().equals(ui.getIdentity()))
                                    .count();
            totalP0Identities =
                    totalP0Identities
                            + page.items().stream()
                                    .filter(ui -> Vot.P0.name().equals(ui.getIdentity()))
                                    .count();
            var pageConstituteVCsTotal =
                    page.items().stream()
                            .map(ReportUserIdentityItem::getConstituentVcs)
                            .filter(Objects::nonNull)
                            .collect(
                                    Collectors.groupingBy(
                                            Function.identity(), Collectors.counting()));
            mergedConstituteVCsTotal =
                    Stream.of(previousConstituteVCsTotal, pageConstituteVCsTotal)
                            .flatMap(map -> map.entrySet().stream())
                            .collect(
                                    Collectors.toMap(
                                            Map.Entry::getKey, Map.Entry::getValue, Long::sum));
            previousConstituteVCsTotal = mergedConstituteVCsTotal;
            reportProcessingResult.setBuildReportLastEvaluatedKey(
                    DynamoDbHelper.unmarshallLastEvaluatedKey(page.lastEvaluatedKey()));

            checkLambdaRemainingExecutionTime(context);
        }
        reportProcessingResult.setBuildReportLastEvaluatedKey(null);
        reportProcessingResult.setSummary(
                new ReportSummary(
                        totalP2Identities,
                        totalP2IdentitiesMigrated,
                        totalP1Identities,
                        totalP0Identities,
                        mergedConstituteVCsTotal));
        LOGGER.info(
                LogHelper.buildLogMessage("Completed building report processing summary result."));
    }

    private void checkLambdaRemainingExecutionTime(Context context)
            throws StopBeforeLambdaTimeoutException {
        if (context.getRemainingTimeInMillis() <= STOP_TIME_IN_MILLISECONDS_BEFORE_LAMBDA_TIMEOUT) {
            throw new StopBeforeLambdaTimeoutException("Stopping as lambda about to timeout.");
        }
    }
}
