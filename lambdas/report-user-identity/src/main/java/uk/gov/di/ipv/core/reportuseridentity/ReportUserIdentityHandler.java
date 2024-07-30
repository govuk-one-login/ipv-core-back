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
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.persistence.DataStore;
import uk.gov.di.ipv.core.library.persistence.item.VcStoreItem;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.reportuseridentity.domain.ReportProcessingResult;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

@ExcludeFromGeneratedCoverageReport
public class ReportUserIdentityHandler implements RequestStreamHandler {
    private static final Logger LOGGER = LogManager.getLogger();
    private static final ObjectMapper objectMapper = new ObjectMapper();
    private final ConfigService configService;
    private final DataStore<VcStoreItem> vcStoreItemDataStore;

    @SuppressWarnings("unused") // Used through dependency injection
    public ReportUserIdentityHandler(
            ConfigService configService,
            DataStore<VcStoreItem> vcStoreItemDataStore,
            DataStore<VcStoreItem> archivedVcDataStore) {
        this.configService = configService;
        this.vcStoreItemDataStore = vcStoreItemDataStore;
    }

    @SuppressWarnings("unused") // Used by AWS
    public ReportUserIdentityHandler() {
        this.configService = ConfigService.create();
        this.vcStoreItemDataStore =
                DataStore.create(
                        EnvironmentVariable.USER_ISSUED_CREDENTIALS_TABLE_NAME,
                        VcStoreItem.class,
                        configService);
    }

    @Override
    @Tracing
    @Logging(clearState = true)
    public void handleRequest(InputStream inputStream, OutputStream outputStream, Context context)
            throws IOException {
        LogHelper.attachComponentId(configService);

        var result = new ReportProcessingResult();
        LOGGER.info(LogHelper.buildLogMessage("Processing report."));

        try {
            LOGGER.info(
                    LogHelper.buildLogMessage(
                            String.format("Completed report processing for user's identity.")));
        } catch (Exception e) {
            LOGGER.error(
                    LogHelper.buildErrorMessage(
                            "Stopped report processing for user's identity.", e));
        } finally {
            objectMapper.enable(SerializationFeature.INDENT_OUTPUT);
            objectMapper.writeValue(outputStream, result);
        }
    }
}
