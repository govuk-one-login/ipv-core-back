package uk.gov.di.ipv.core.library.tracing;

import io.opentelemetry.api.trace.Span;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@ExcludeFromGeneratedCoverageReport
public class InstrumentationHelper {
    private static final Logger LOGGER = LogManager.getLogger();

    private InstrumentationHelper() {
        throw new IllegalStateException("Utility class");
    }

    public static void setSpanAttribute(String name, String value) {
        try {
            Span span = Span.current();
            span.setAttribute(name, value);
        } catch (Exception e) {
            LOGGER.warn(String.format("Failed to instrument span attribute: %s", name));
        }
    }
}
