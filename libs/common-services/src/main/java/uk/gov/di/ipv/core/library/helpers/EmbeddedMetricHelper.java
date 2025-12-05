package uk.gov.di.ipv.core.library.helpers;

import lombok.AllArgsConstructor;
import lombok.Getter;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.ThreadContext;
import software.amazon.lambda.powertools.metrics.Metrics;
import software.amazon.lambda.powertools.metrics.MetricsFactory;
import software.amazon.lambda.powertools.metrics.model.DimensionSet;
import software.amazon.lambda.powertools.metrics.model.MetricResolution;
import software.amazon.lambda.powertools.metrics.model.MetricUnit;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.enums.Vot;
import uk.gov.di.ipv.core.library.gpg45.enums.Gpg45Profile;

import java.util.List;
import java.util.Map;

import static uk.gov.di.ipv.core.library.helpers.EmbeddedMetricHelper.Dimension.ACHIEVED_VOT;
import static uk.gov.di.ipv.core.library.helpers.EmbeddedMetricHelper.Dimension.CRI;
import static uk.gov.di.ipv.core.library.helpers.EmbeddedMetricHelper.Dimension.CRI_ERROR_CODE;
import static uk.gov.di.ipv.core.library.helpers.EmbeddedMetricHelper.Dimension.PROFILE;
import static uk.gov.di.ipv.core.library.helpers.EmbeddedMetricHelper.Dimension.QUEUE_NAME;
import static uk.gov.di.ipv.core.library.helpers.EmbeddedMetricHelper.Dimension.REQUESTED_VTR;
import static uk.gov.di.ipv.core.library.helpers.EmbeddedMetricHelper.Metric.ASYNC_CRI_ERROR_RESPONSE;
import static uk.gov.di.ipv.core.library.helpers.EmbeddedMetricHelper.Metric.ASYNC_CRI_RESPONSE_MESSAGE_UNEXPECTED;
import static uk.gov.di.ipv.core.library.helpers.EmbeddedMetricHelper.Metric.CRI_REDIRECT;
import static uk.gov.di.ipv.core.library.helpers.EmbeddedMetricHelper.Metric.CRI_RETURN;
import static uk.gov.di.ipv.core.library.helpers.EmbeddedMetricHelper.Metric.IDENTITY_ISSUED;
import static uk.gov.di.ipv.core.library.helpers.EmbeddedMetricHelper.Metric.IDENTITY_JOURNEY_COMPLETE;
import static uk.gov.di.ipv.core.library.helpers.EmbeddedMetricHelper.Metric.IDENTITY_JOURNEY_START;
import static uk.gov.di.ipv.core.library.helpers.EmbeddedMetricHelper.Metric.IDENTITY_PROVING;
import static uk.gov.di.ipv.core.library.helpers.EmbeddedMetricHelper.Metric.IDENTITY_REUSE;
import static uk.gov.di.ipv.core.library.helpers.EmbeddedMetricHelper.Metric.PROFILE_MATCH;
import static uk.gov.di.ipv.core.library.helpers.EmbeddedMetricHelper.Metric.REVERIFY_JOURNEY_COMPLETE;
import static uk.gov.di.ipv.core.library.helpers.EmbeddedMetricHelper.Metric.REVERIFY_JOURNEY_START;

@ExcludeFromGeneratedCoverageReport
public class EmbeddedMetricHelper {
    private static final Metrics METRICS_LOGGER = MetricsFactory.getMetricsInstance();
    private static final Logger LOGGER = LogManager.getLogger();

    @Getter
    @AllArgsConstructor
    @ExcludeFromGeneratedCoverageReport
    public enum Metric {
        CRI_REDIRECT("criRedirect"),
        CRI_RETURN("criReturn"),
        ASYNC_CRI_RESPONSE_MESSAGE_UNEXPECTED("asyncCriResponseMessageUnexpected"),
        ASYNC_CRI_ERROR_RESPONSE("asyncCriErrorResponse"),
        IDENTITY_ISSUED("identityIssued"),
        IDENTITY_JOURNEY_START("identityJourneyStart"),
        IDENTITY_JOURNEY_COMPLETE("identityJourneyComplete"),
        IDENTITY_PROVING("identityProving"),
        IDENTITY_REUSE("identityReuse"),
        PROFILE_MATCH("profileMatch"),
        REVERIFY_JOURNEY_START("reverifyJourneyStart"),
        REVERIFY_JOURNEY_COMPLETE("reverifyJourneyComplete");

        private final String name;
    }

    @Getter
    @AllArgsConstructor
    @ExcludeFromGeneratedCoverageReport
    public enum Dimension {
        CRI("cri"),
        QUEUE_NAME("queueName"),
        CRI_ERROR_CODE("cri_errorCode"),
        ERROR_MESSAGE("errorMessage"),
        ACHIEVED_VOT("achievedVot"),
        REQUESTED_VTR("requestedVtr"),
        PROFILE("profile");

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
                Map.of(CRI_ERROR_CODE, String.format("%s_%s", criId, errorCode)),
                Map.of(ASYNC_CRI_ERROR_RESPONSE, 1.0));
    }

    public static void identityIssued(Vot achievedVot) {
        recordMetric(Map.of(ACHIEVED_VOT, achievedVot.name()), Map.of(IDENTITY_ISSUED, 1.0));
    }

    public static void identityJourneyStart(List<String> requestedVtr) {
        recordMetric(
                Map.of(REQUESTED_VTR, String.join(",", requestedVtr)),
                Map.of(IDENTITY_JOURNEY_START, 1.0));
    }

    public static void identityJourneyComplete() {
        recordMetric(Map.of(IDENTITY_JOURNEY_COMPLETE, 1.0));
    }

    public static void identityReuse() {
        recordHighResolutionMetric(Map.of(), Map.of(IDENTITY_REUSE, 1.0));
    }

    public static void identityProving() {
        recordHighResolutionMetric(Map.of(), Map.of(IDENTITY_PROVING, 1.0));
    }

    public static void profileMatch(Gpg45Profile matchedProfile) {
        recordMetric(Map.of(PROFILE, matchedProfile.getLabel()), Map.of(PROFILE_MATCH, 1.0));
    }

    public static void reverifyJourneyStart() {
        recordMetric(Map.of(REVERIFY_JOURNEY_START, 1.0));
    }

    public static void reverifyJourneyComplete() {
        recordMetric(Map.of(REVERIFY_JOURNEY_COMPLETE, 1.0));
    }

    private static void recordMetric(Map<Metric, Double> metrics) {
        recordMetric(Map.of(), metrics);
    }

    private static void recordHighResolutionMetric(
            Map<Dimension, String> dimensions, Map<Metric, Double> metrics) {
        recordMetric(dimensions, metrics, MetricResolution.HIGH);
    }

    private static void recordMetric(
            Map<Dimension, String> dimensions, Map<Metric, Double> metrics) {
        recordMetric(dimensions, metrics, MetricResolution.STANDARD);
    }

    private static void recordMetric(
            Map<Dimension, String> dimensions,
            Map<Metric, Double> metrics,
            MetricResolution resolution) {
        try {
            ThreadContext.getContext().forEach(METRICS_LOGGER::addMetadata);
            dimensions.forEach(
                    (dimension, value) ->
                            METRICS_LOGGER.addDimension(
                                    DimensionSet.of(dimension.getName(), value)));
            metrics.forEach(
                    (metric, value) ->
                            METRICS_LOGGER.addMetric(
                                    metric.getName(), value, MetricUnit.COUNT, resolution));
        } catch (Exception e) {
            LOGGER.warn("Failed to record embedded metric", e);
        }
    }
}
