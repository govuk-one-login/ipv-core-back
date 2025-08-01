package uk.gov.di.ipv.core.validateappconfig;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.lambda.powertools.logging.Logging;
import software.amazon.lambda.powertools.metrics.Metrics;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.service.ConfigService;

import java.util.Map;

public class ValidateAppConfigHandler implements RequestHandler<Map<String, Object>, Object> {
    private static final Logger LOGGER = LogManager.getLogger();

    @Override
    @Logging(clearState = true)
    @Metrics(captureColdStart = true)
    public Object handleRequest(Map<String, Object> input, Context context) {
        LogHelper.attachTraceId();

        try {
            var content = input.get("content").toString();
            ConfigService.generateConfiguration(content);
            return true;
        } catch (Exception e) {
            LOGGER.error(LogHelper.buildErrorMessage("Unhandled lambda exception", e));
            throw e;
        }
    }
}
