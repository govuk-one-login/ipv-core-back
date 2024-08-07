package uk.gov.di.ipv.core.reportuseridentity;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestStreamHandler;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.awssdk.services.dynamodb.model.AttributeValue;
import software.amazon.lambda.powertools.logging.Logging;
import software.amazon.lambda.powertools.tracing.Tracing;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.config.EnvironmentVariable;
import uk.gov.di.ipv.core.library.enums.Vot;
import uk.gov.di.ipv.core.library.exceptions.BatchDeleteException;
import uk.gov.di.ipv.core.library.exceptions.CredentialParseException;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.persistence.item.VcStoreItem;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.UserIdentityService;
import uk.gov.di.ipv.core.library.verifiablecredential.service.VerifiableCredentialService;
import uk.gov.di.ipv.core.reportuseridentity.domain.ReportProcessingRequest;
import uk.gov.di.ipv.core.reportuseridentity.domain.ReportProcessingResult;
import uk.gov.di.ipv.core.reportuseridentity.domain.ReportSummary;
import uk.gov.di.ipv.core.reportuseridentity.domain.TableScanResult;
import uk.gov.di.ipv.core.reportuseridentity.persistence.DataStore;
import uk.gov.di.ipv.core.reportuseridentity.persistence.item.ReportUserIdentityItem;
import uk.gov.di.ipv.core.reportuseridentity.service.ReportUserIdentityService;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

@ExcludeFromGeneratedCoverageReport
public class ReportUserIdentityHandler implements RequestStreamHandler {
    public static final String ATTR_NAME_USER_ID = "userId";
    private static final Logger LOGGER = LogManager.getLogger();
    private final ObjectMapper objectMapper;
    private final ConfigService configService;
    private final UserIdentityService userIdentityService;
    private final VerifiableCredentialService verifiableCredentialService;
    private final ReportUserIdentityService reportUserIdentityService;
    private final DataStore<VcStoreItem> vcStoreItemDataStore;
    private final DataStore<ReportUserIdentityItem> reportUserIdentityDataStore;

    @SuppressWarnings("unused") // Used through dependency injection
    public ReportUserIdentityHandler(
            ObjectMapper objectMapper,
            ConfigService configService,
            UserIdentityService userIdentityService,
            VerifiableCredentialService verifiableCredentialService,
            ReportUserIdentityService reportUserIdentityService,
            DataStore<VcStoreItem> vcStoreItemDataStore,
            DataStore<ReportUserIdentityItem> reportUserIdentityDataStore) {
        this.objectMapper = objectMapper;
        this.configService = configService;
        this.userIdentityService = userIdentityService;
        this.verifiableCredentialService = verifiableCredentialService;
        this.reportUserIdentityService = reportUserIdentityService;
        this.vcStoreItemDataStore = vcStoreItemDataStore;
        this.reportUserIdentityDataStore = reportUserIdentityDataStore;
    }

    @SuppressWarnings("unused") // Used by AWS
    public ReportUserIdentityHandler() {
        this.objectMapper = new ObjectMapper();
        this.configService = ConfigService.create();
        this.userIdentityService = new UserIdentityService(configService);
        this.verifiableCredentialService = new VerifiableCredentialService(configService);
        this.reportUserIdentityService = new ReportUserIdentityService();
        this.vcStoreItemDataStore =
                new DataStore<>(
                        configService.getEnvironmentVariable(
                                EnvironmentVariable.USER_ISSUED_CREDENTIALS_TABLE_NAME),
                        VcStoreItem.class,
                        DataStore.getClient());
        this.reportUserIdentityDataStore =
                new DataStore<>(
                        configService.getEnvironmentVariable(
                                EnvironmentVariable.REPORT_USER_IDENTITY_TABLE_NAME),
                        ReportUserIdentityItem.class,
                        DataStore.getClient());
    }

    @Override
    @Tracing
    @Logging(clearState = true)
    public void handleRequest(InputStream inputStream, OutputStream outputStream, Context context)
            throws IOException {
        LogHelper.attachComponentId(configService);
        LOGGER.info(LogHelper.buildLogMessage("Processing report." + inputStream));

        ReportProcessingResult.ReportProcessingResultBuilder reportProcessingResult =
                ReportProcessingResult.builder();
        try {
            ReportProcessingRequest reportProcessingRequest =
                    objectMapper.readValue(inputStream, ReportProcessingRequest.class);
            LOGGER.info(LogHelper.buildLogMessage("request." + reportProcessingRequest.toString()));
            List<String> userIds = new ArrayList<>();
            if ((!reportProcessingRequest.continueUserScan()
                            && (reportProcessingRequest.lastEvaluatedKey() == null))
                    || reportProcessingRequest.continueUserScan()) {
                LOGGER.info(
                        LogHelper.buildLogMessage(
                                "Retrieving userIds from tactical store db table."));

                Map<String, AttributeValue> exclusiveStartKey =
                        reportProcessingRequest.continueUserScan()
                                ? reportProcessingRequest.lastEvaluatedKey()
                                : null;

                do {
                    TableScanResult<VcStoreItem> tableScanResult =
                            vcStoreItemDataStore.getItems(exclusiveStartKey, ATTR_NAME_USER_ID);
                    userIds.addAll(
                            tableScanResult.items().stream()
                                    .map(VcStoreItem::getUserId)
                                    .distinct()
                                    .toList());

                    List<ReportUserIdentityItem> reportUserIdentities =
                            userIds.stream()
                                    .map(
                                            usrId ->
                                                    new ReportUserIdentityItem(
                                                            usrId,
                                                            null,
                                                            0,
                                                            Collections.emptyList(),
                                                            false))
                                    .toList();
                    reportUserIdentityDataStore.createOrUpdate(reportUserIdentities);
                    if (tableScanResult.lastEvaluatedKey() != null) {
                        exclusiveStartKey = tableScanResult.lastEvaluatedKey();
                        reportProcessingResult.tacticalStoreLastEvaluatedKey(exclusiveStartKey);
                    }
                } while (exclusiveStartKey != null);
                LOGGER.info(
                        LogHelper.buildLogMessage(
                                "Tactical storage scan completed to get unique users."));
            }

            //
            processUsersToFindLOCAndUpdateDb(userIds);
            //
            reportProcessingResult = buildReportProcessingResult(reportProcessingResult);

            LOGGER.info(
                    LogHelper.buildLogMessage("Completed report processing for user's identity."));
        } catch (HttpResponseExceptionWithErrorBody | CredentialParseException | ParseException e) {
            LOGGER.error(
                    LogHelper.buildErrorMessage(
                            "Stopped report processing of user's identity.", e));
        } catch (BatchDeleteException e) {
            LOGGER.info(LogHelper.buildLogMessage("Error occurred during batch write process."));
        } finally {
            LOGGER.info(LogHelper.buildLogMessage("Writing output with result summary."));
            objectMapper.enable(SerializationFeature.INDENT_OUTPUT);
            objectMapper.writeValue(outputStream, reportProcessingResult.build());
        }
    }

    private void processUsersToFindLOCAndUpdateDb(List<String> userIds)
            throws CredentialParseException, HttpResponseExceptionWithErrorBody, ParseException,
                    BatchDeleteException {
        LOGGER.info(
                LogHelper.buildLogMessage(
                        String.format("Checking identity for total (%s) users.", userIds.size())));
        List<ReportUserIdentityItem> reportUserIdentityItems = new ArrayList<>();
        for (String userId : userIds) {
            var tacticalVcs = verifiableCredentialService.getVcs(userId);
            if (!userIdentityService.areVcsCorrelated(tacticalVcs)) {
                LOGGER.info(
                        LogHelper.buildLogMessage(
                                String.format("User (%s) VCs not correlated.", userId)));
                continue;
            }
            boolean anyVCsMigrated = tacticalVcs.stream().anyMatch(vc -> vc.getMigrated() != null);
            boolean allVCsMigrated = tacticalVcs.stream().allMatch(vc -> vc.getMigrated() != null);

            if (anyVCsMigrated && !allVCsMigrated) {
                LOGGER.info(
                        LogHelper.buildLogMessage(
                                String.format(
                                        "Not all VCs are migrated for this user (%s).", userId)));
            }
            var votAttained =
                    reportUserIdentityService.getStrongestAttainedVotForCredentials(tacticalVcs);

            reportUserIdentityItems.add(
                    new ReportUserIdentityItem(
                            userId,
                            votAttained.orElse(Vot.P0).name(),
                            tacticalVcs.size(),
                            reportUserIdentityService.getIdentityConstituent(tacticalVcs),
                            allVCsMigrated));
        }
        LOGGER.info(LogHelper.buildLogMessage("Updating processed user's identity."));
        reportUserIdentityDataStore.createOrUpdate(reportUserIdentityItems);
    }

    private ReportProcessingResult.ReportProcessingResultBuilder buildReportProcessingResult(
            ReportProcessingResult.ReportProcessingResultBuilder reportProcessingResult) {
        LOGGER.info(LogHelper.buildLogMessage("Building report processing summary result."));
        Map<String, AttributeValue> exclusiveStartKey = null;
        List<ReportUserIdentityItem> userIdentities = new ArrayList<>();
        do {
            TableScanResult<ReportUserIdentityItem> tableScanResult =
                    reportUserIdentityDataStore.getItems(exclusiveStartKey, "identity", "migrated");
            userIdentities.addAll(tableScanResult.items());
            if (tableScanResult.lastEvaluatedKey() != null) {
                exclusiveStartKey = tableScanResult.lastEvaluatedKey();
            }
        } while (exclusiveStartKey != null);

        List<ReportUserIdentityItem> totalP2Identities =
                userIdentities.stream()
                        .filter(ui -> Vot.P2.name().equals(ui.getIdentity()))
                        .toList();
        long totalP2 = totalP2Identities.size();
        long totalP2Migrated =
                totalP2Identities.stream()
                        .filter(item -> (Boolean.TRUE.equals(item.getMigrated())))
                        .toList()
                        .size();
        long totalPCL250 =
                userIdentities.stream()
                        .filter(ui -> Vot.PCL250.name().equals(ui.getIdentity()))
                        .toList()
                        .size();
        long totalPCL200 =
                userIdentities.stream()
                        .filter(ui -> Vot.PCL200.name().equals(ui.getIdentity()))
                        .toList()
                        .size();
        long totalP1 =
                userIdentities.stream()
                        .filter(ui -> Vot.P1.name().equals(ui.getIdentity()))
                        .toList()
                        .size();
        long totalP0 =
                userIdentities.stream()
                        .filter(ui -> Vot.P0.name().equals(ui.getIdentity()))
                        .toList()
                        .size();
        return reportProcessingResult.summary(
                new ReportSummary(
                        totalP2, totalP2Migrated, totalPCL250, totalPCL200, totalP1, totalP0));
    }
}
