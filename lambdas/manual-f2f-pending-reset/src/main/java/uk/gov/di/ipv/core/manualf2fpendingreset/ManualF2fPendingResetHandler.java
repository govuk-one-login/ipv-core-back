package uk.gov.di.ipv.core.manualf2fpendingreset;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.lambda.powertools.logging.Logging;
import software.amazon.lambda.powertools.metrics.Metrics;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.criresponse.service.CriResponseService;
import uk.gov.di.ipv.core.library.domain.Cri;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.persistence.item.CriResponseItem;
import uk.gov.di.ipv.core.library.service.ConfigService;

import java.util.HashMap;
import java.util.Map;

public class ManualF2fPendingResetHandler implements RequestHandler<String, Map<String, Object>> {

    private static final Logger LOGGER = LogManager.getLogger();

    private static final String RESULT_KEY = "result";
    private static final String MESSAGE_KEY = "message";
    private static final String RESULT_ERROR = "error";
    private static final String RESULT_SUCCESS = "success";

    private final CriResponseService criResponseService;
    private final ConfigService configService;

    @ExcludeFromGeneratedCoverageReport
    public ManualF2fPendingResetHandler() {
        this.configService = ConfigService.create();
        this.criResponseService = new CriResponseService(configService);
    }

    public ManualF2fPendingResetHandler(
            CriResponseService criResponseService, ConfigService configService) {
        this.criResponseService = criResponseService;
        this.configService = configService;
    }

    @Override
    @Logging(clearState = true)
    @Metrics(captureColdStart = true)
    public Map<String, Object> handleRequest(String input, Context context) {
        LogHelper.attachTraceId();
        LogHelper.attachComponentId(configService);

        Map<String, Object> response = new HashMap<>();

        if (input == null || input.isBlank()) {
            LOGGER.error(LogHelper.buildLogMessage("No userId provided in input"));
            response.put(RESULT_KEY, RESULT_ERROR);
            response.put(MESSAGE_KEY, "Missing or empty userId in input");
            return response;
        }

        try {
            CriResponseItem item = criResponseService.getCriResponseItem(input, Cri.F2F);

            if (item == null) {
                LOGGER.error(LogHelper.buildLogMessage("No F2F pending record found"));
                response.put(RESULT_KEY, RESULT_ERROR);
                response.put(MESSAGE_KEY, "No F2F pending record found.");
                return response;
            }

            criResponseService.deleteCriResponseItem(input, Cri.F2F);
            LOGGER.info(LogHelper.buildLogMessage("Successfully deleted F2F pending record"));
            response.put(RESULT_KEY, RESULT_SUCCESS);
            response.put(MESSAGE_KEY, "Deleted F2F pending record.");
        } catch (Exception e) {
            LOGGER.error(LogHelper.buildErrorMessage("Failed to delete record", e));
            response.put(RESULT_KEY, RESULT_ERROR);
            response.put(MESSAGE_KEY, "Failed to delete record due to internal error.");
        }

        return response;
    }
}
