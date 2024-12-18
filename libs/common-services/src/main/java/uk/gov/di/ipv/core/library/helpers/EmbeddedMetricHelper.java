package uk.gov.di.ipv.core.library.helpers;

import lombok.AllArgsConstructor;
import lombok.Getter;
import org.apache.logging.log4j.ThreadContext;
import software.amazon.cloudwatchlogs.emf.logger.MetricsLogger;
import software.amazon.cloudwatchlogs.emf.model.DimensionSet;
import software.amazon.lambda.powertools.metrics.MetricsUtils;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

import java.util.Map;

import static uk.gov.di.ipv.core.library.helpers.EmbeddedMetricHelper.Dimension.CRI;
import static uk.gov.di.ipv.core.library.helpers.EmbeddedMetricHelper.Metric.CRI_REDIRECT;
import static uk.gov.di.ipv.core.library.helpers.EmbeddedMetricHelper.Metric.CRI_RETURN;

@ExcludeFromGeneratedCoverageReport
public class EmbeddedMetricHelper {
    private static final MetricsLogger METRICS_LOGGER = MetricsUtils.metricsLogger();

    @Getter
    @AllArgsConstructor
    @ExcludeFromGeneratedCoverageReport
    public enum Metric {
        CRI_REDIRECT("criRedirect"),
        CRI_RETURN("criReturn");

        private final String name;
    }

    @Getter
    @AllArgsConstructor
    @ExcludeFromGeneratedCoverageReport
    public enum Dimension {
        CRI("cri");

        private final String name;
    }

    public static void criRedirect(String cri) {
        recordMetric(Map.of(CRI, cri), Map.of(CRI_REDIRECT, 1.0));
    }

    public static void criReturn(String cri) {
        recordMetric(Map.of(CRI, cri), Map.of(CRI_RETURN, 1.0));
    }

    private static void recordMetric(
            Map<Dimension, String> dimensions, Map<Metric, Double> metrics) {
        ThreadContext.getContext().forEach(METRICS_LOGGER::putProperty);
        dimensions.forEach(
                (dimension, value) ->
                        METRICS_LOGGER.putDimensions(DimensionSet.of(dimension.getName(), value)));
        metrics.forEach((metric, value) -> METRICS_LOGGER.putMetric(metric.getName(), value));
    }
}
