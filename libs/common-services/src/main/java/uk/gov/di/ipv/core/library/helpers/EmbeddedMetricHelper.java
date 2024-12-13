package uk.gov.di.ipv.core.library.helpers;

import lombok.AllArgsConstructor;
import lombok.Getter;
import software.amazon.cloudwatchlogs.emf.logger.MetricsLogger;
import software.amazon.cloudwatchlogs.emf.model.DimensionSet;
import software.amazon.lambda.powertools.metrics.MetricsUtils;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

import java.util.Map;

import static uk.gov.di.ipv.core.library.helpers.EmbeddedMetricHelper.Dimension.CRI;
import static uk.gov.di.ipv.core.library.helpers.EmbeddedMetricHelper.Metric.CRI_REDIRECT;
import static uk.gov.di.ipv.core.library.helpers.EmbeddedMetricHelper.Metric.CRI_RETURN;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.GOVUK_SIGNIN_JOURNEY_ID_DEFAULT_VALUE;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_GOVUK_SIGNIN_JOURNEY_ID;

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

    public static void criRedirect(String cri, String govukSigninJourneyId) {
        createMetrics(Map.of(CRI, cri), Map.of(CRI_REDIRECT, 1.0), govukSigninJourneyId);
    }

    public static void criReturn(String cri, String govukSigninJourneyId) {
        createMetrics(Map.of(CRI, cri), Map.of(CRI_RETURN, 1.0), govukSigninJourneyId);
    }

    private static void createMetrics(
            Map<Dimension, String> dimensions,
            Map<Metric, Double> metrics,
            String govukSigninJourneyId) {
        METRICS_LOGGER.putProperty(
                LOG_GOVUK_SIGNIN_JOURNEY_ID.getFieldName(),
                govukSigninJourneyId == null
                        ? GOVUK_SIGNIN_JOURNEY_ID_DEFAULT_VALUE
                        : govukSigninJourneyId);
        dimensions.forEach(
                (dimension, value) ->
                        METRICS_LOGGER.putDimensions(DimensionSet.of(dimension.getName(), value)));
        metrics.forEach((metric, value) -> METRICS_LOGGER.putMetric(metric.getName(), value));
    }
}
