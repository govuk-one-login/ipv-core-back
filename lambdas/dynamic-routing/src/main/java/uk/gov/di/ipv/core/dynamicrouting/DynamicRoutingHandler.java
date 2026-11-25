package uk.gov.di.ipv.core.dynamicrouting;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.message.StringMapMessage;
import software.amazon.lambda.powertools.logging.Logging;
import software.amazon.lambda.powertools.metrics.FlushMetrics;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.domain.JourneyResponse;
import uk.gov.di.ipv.core.library.domain.ProcessRequest;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.service.ConfigService;

import java.util.Map;

import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_MESSAGE_DESCRIPTION;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_NEXT_PATH;

public class DynamicRoutingHandler implements RequestHandler<ProcessRequest, Map<String, Object>> {
    private static final Logger LOGGER = LogManager.getLogger();
    private final ConfigService configService;

    @SuppressWarnings("unused") // Used by AWS
    @ExcludeFromGeneratedCoverageReport
    public DynamicRoutingHandler() {
        this(ConfigService.create());
    }

    public DynamicRoutingHandler(ConfigService configService) {
        this.configService = configService;
    }

    @Override
    @Logging(clearState = true)
    @FlushMetrics(captureColdStart = true)
    public Map<String, Object> handleRequest(ProcessRequest event, Context context) {
        LogHelper.attachTraceId();
        LogHelper.attachComponentId(configService);

        try {
            // TODO: implement dynamic routing. For now always route to the next journey event.
            LOGGER.info(
                    new StringMapMessage()
                            .with(
                                    LOG_MESSAGE_DESCRIPTION.getFieldName(),
                                    "Dynamic routing called"));
            return new JourneyResponse(JOURNEY_NEXT_PATH).toObjectMap();
        } catch (Exception e) {
            LOGGER.error(LogHelper.buildErrorMessage("Unhandled lambda exception", e));
            throw e;
        }
    }
}
