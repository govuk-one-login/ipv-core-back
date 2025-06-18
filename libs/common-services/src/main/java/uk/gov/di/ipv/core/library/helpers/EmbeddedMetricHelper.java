package uk.gov.di.ipv.core.library.helpers;

import lombok.AllArgsConstructor;
import lombok.Getter;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.ThreadContext;
import software.amazon.cloudwatchlogs.emf.logger.MetricsLogger;
import software.amazon.cloudwatchlogs.emf.model.DimensionSet;
import software.amazon.lambda.powertools.metrics.MetricsUtils;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

import java.util.Map;

import static uk.gov.di.ipv.core.library.helpers.EmbeddedMetricHelper.Dimension.CRI;
import static uk.gov.di.ipv.core.library.helpers.EmbeddedMetricHelper.Dimension.ERROR_CODE;
import static uk.gov.di.ipv.core.library.helpers.EmbeddedMetricHelper.Dimension.QUEUE_NAME;
import static uk.gov.di.ipv.core.library.helpers.EmbeddedMetricHelper.Metric.ASYNC_CRI_ERROR_RESPONSE;
import static uk.gov.di.ipv.core.library.helpers.EmbeddedMetricHelper.Metric.ASYNC_CRI_RESPONSE_MESSAGE_UNEXPECTED;
import static uk.gov.di.ipv.core.library.helpers.EmbeddedMetricHelper.Metric.CRI_REDIRECT;
import static uk.gov.di.ipv.core.library.helpers.EmbeddedMetricHelper.Metric.CRI_RETURN;

@ExcludeFromGeneratedCoverageReport
public class EmbeddedMetricHelper {
    private static final MetricsLogger METRICS_LOGGER = MetricsUtils.metricsLogger();
    private static final Logger LOGGER = LogManager.getLogger();

    @Getter
    @AllArgsConstructor
    @ExcludeFromGeneratedCoverageReport
    public enum Metric {
        CRI_REDIRECT("criRedirect"),
        CRI_RETURN("criReturn"),
        ASYNC_CRI_RESPONSE_MESSAGE_UNEXPECTED("asyncCriResponseMessageUnexpected"),
        ASYNC_CRI_ERROR_RESPONSE("asyncCriErrorResponse");

        private final String name;
    }

    @Getter
    @AllArgsConstructor
    @ExcludeFromGeneratedCoverageReport
    public enum Dimension {
        CRI("cri"),
        QUEUE_NAME("queueName"),
        ERROR_CODE("errorCode"),
        ERROR_MESSAGE("errorMessage");

        private final String name;
    }

    public static void criRedirect(String criId) {
        recordMetric(Map.of(CRI, criId), Map.of(CRI_REDIRECT, 1.0));
    }

    public static void criReturn(String criId) {
        recordMetric(Map.of(CRI, criId), Map.of(CRI_RETURN, 1.0));
    }

    public static void asyncCriResponseUnexpected(String queueName) {
        recordMetric(
                Map.of(QUEUE_NAME, queueName), Map.of(ASYNC_CRI_RESPONSE_MESSAGE_UNEXPECTED, 1.0));
    }

    public static void asyncCriErrorResponse(String criId, String errorCode) {
        recordMetric(
                Map.of(CRI, criId, ERROR_CODE, errorCode), Map.of(ASYNC_CRI_ERROR_RESPONSE, 1.0));
    }

    private static void recordMetric(
            Map<Dimension, String> dimensions, Map<Metric, Double> metrics) {
        try {
            ThreadContext.getContext().forEach(METRICS_LOGGER::putProperty);
            dimensions.forEach(
                    (dimension, value) ->
                            METRICS_LOGGER.putDimensions(
                                    DimensionSet.of(dimension.getName(), value)));
            metrics.forEach((metric, value) -> METRICS_LOGGER.putMetric(metric.getName(), value));
        } catch (Exception e) {
            LOGGER.warn("Failed to record embedded metric", e);
        }
    }
}
