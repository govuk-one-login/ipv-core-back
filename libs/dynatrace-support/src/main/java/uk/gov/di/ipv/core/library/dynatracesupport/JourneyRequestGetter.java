package uk.gov.di.ipv.core.library.dynatracesupport;

import io.opentelemetry.context.propagation.TextMapGetter;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.ipv.core.library.domain.JourneyRequest;
import uk.gov.di.ipv.core.library.helpers.LogHelper;

public class JourneyRequestGetter implements TextMapGetter<JourneyRequest> {
    private static final Logger LOGGER = LogManager.getLogger();

    @Override
    public Iterable<String> keys(JourneyRequest carrier) {
        return null;
    }

    @Override
    public String get(JourneyRequest carrier, String key) {
        return switch (key) {
            case "traceparent" -> carrier.getTraceParent();
            case "tracestate" -> carrier.getTraceState();
            default -> {
                LOGGER.warn(
                        LogHelper.buildLogMessage("Invalid key provid for trace propogation")
                                .with("key", key));
                yield null;
            }
        };
    }
}
