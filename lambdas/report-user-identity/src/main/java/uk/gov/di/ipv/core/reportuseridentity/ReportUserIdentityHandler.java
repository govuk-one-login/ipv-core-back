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
import uk.gov.di.ipv.core.library.persistence.DataStore;
import uk.gov.di.ipv.core.library.persistence.item.VcStoreItem;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.UserIdentityService;
import uk.gov.di.ipv.core.library.verifiablecredential.service.VerifiableCredentialService;
import uk.gov.di.ipv.core.reportuseridentity.domain.ReportProcessingResult;
import uk.gov.di.ipv.core.reportuseridentity.domain.ReportSummary;
import uk.gov.di.ipv.core.reportuseridentity.domain.item.ReportUserIdentityItem;
import uk.gov.di.ipv.core.reportuseridentity.service.ReportUserIdentityService;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

@ExcludeFromGeneratedCoverageReport
public class ReportUserIdentityHandler implements RequestStreamHandler {
    private static final Logger LOGGER = LogManager.getLogger();
    public static final String ATTR_NAME_TO_SUMMARISE_ON = "identity";
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
                DataStore.create(
                        EnvironmentVariable.USER_ISSUED_CREDENTIALS_TABLE_NAME,
                        VcStoreItem.class,
                        configService);
        this.reportUserIdentityDataStore =
                DataStore.create(
                        EnvironmentVariable.REPORT_USER_IDENTITY_TABLE_NAME,
                        ReportUserIdentityItem.class,
                        configService);
    }

    @Override
    @Tracing
    @Logging(clearState = true)
    public void handleRequest(InputStream inputStream, OutputStream outputStream, Context context)
            throws IOException {
        LogHelper.attachComponentId(configService);

        LOGGER.info(LogHelper.buildLogMessage("Processing report."));

        try {
            var userIds =
                    vcStoreItemDataStore.getItems().stream()
                            .map(VcStoreItem::getUserId)
                            .distinct()
                            .toList();
            List<ReportUserIdentityItem> reportUserIdentities =
                    userIds.stream()
                            .map(
                                    usrId ->
                                            new ReportUserIdentityItem(
                                                    usrId,
                                                    Vot.P0.name(),
                                                    Collections.emptyList(),
                                                    null))
                            .toList();
            reportUserIdentityDataStore.createOrUpdate(reportUserIdentities);

            List<ReportUserIdentityItem> reportUserIdentityItems = new ArrayList<>();
            LOGGER.info(
                    LogHelper.buildLogMessage(
                            String.format(
                                    "Checking identity for total (%s) users.", userIds.size())));
            for (String userId : userIds) {
                var tacticalVcs = verifiableCredentialService.getVcs(userId);
                if (!userIdentityService.areVcsCorrelated(tacticalVcs)) {
                    LOGGER.info(
                            LogHelper.buildLogMessage(
                                    String.format("User (%s) VCs not correlated.", userId)));
                    continue;
                }
                boolean migrated = tacticalVcs.stream().allMatch(vc -> vc.getMigrated() != null);
                var votAttained =
                        reportUserIdentityService.getStrongestAttainedVotForVtr(tacticalVcs);

                reportUserIdentityItems.add(
                        new ReportUserIdentityItem(
                                userId,
                                votAttained.orElse(Vot.P0).name(),
                                reportUserIdentityService.getIdentityConstituent(tacticalVcs),
                                migrated));
            }
            LOGGER.info(LogHelper.buildLogMessage("Updating processed user's identity."));
            reportUserIdentityDataStore.createOrUpdate(reportUserIdentityItems);

            LOGGER.info(
                    LogHelper.buildLogMessage("Completed report processing for user's identity."));
        } catch (HttpResponseExceptionWithErrorBody | CredentialParseException | ParseException e) {
            LOGGER.error(
                    LogHelper.buildErrorMessage(
                            "Stopped report processing of user's identity.", e));
        } catch (BatchDeleteException e) {
            LOGGER.info(LogHelper.buildLogMessage("Error occurred during batch write process."));
        } finally {
            LOGGER.info(LogHelper.buildLogMessage("Write output with result summary."));
            objectMapper.enable(SerializationFeature.INDENT_OUTPUT);
            objectMapper.writeValue(outputStream, buildReportProcessingResult());
        }
    }

    private ReportProcessingResult buildReportProcessingResult() {
        LOGGER.info(LogHelper.buildLogMessage("Building report processing summary result."));
        List<ReportUserIdentityItem> totalP2Identities =
                reportUserIdentityDataStore.getItems(ATTR_NAME_TO_SUMMARISE_ON, Vot.P2.name());
        long totalP2 = totalP2Identities.size();
        long totalP2Migrated =
                totalP2Identities.stream().filter(ReportUserIdentityItem::getMigrated).count();
        long totalPCL250 =
                reportUserIdentityDataStore
                        .getItems(ATTR_NAME_TO_SUMMARISE_ON, Vot.PCL250.name())
                        .size();
        long totalPCL200 =
                reportUserIdentityDataStore
                        .getItems(ATTR_NAME_TO_SUMMARISE_ON, Vot.PCL200.name())
                        .size();
        long totalP1 =
                reportUserIdentityDataStore
                        .getItems(ATTR_NAME_TO_SUMMARISE_ON, Vot.P1.name())
                        .size();
        long totalP0 =
                reportUserIdentityDataStore
                        .getItems(ATTR_NAME_TO_SUMMARISE_ON, Vot.P0.name())
                        .size();
        return ReportProcessingResult.builder()
                .summary(
                        new ReportSummary(
                                totalP2,
                                totalP2Migrated,
                                totalPCL250,
                                totalPCL200,
                                totalP1,
                                totalP0))
                .build();
    }
}
