package uk.gov.di.ipv.core.fetchsystemsettings;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.lambda.powertools.logging.Logging;
import software.amazon.lambda.powertools.metrics.Metrics;
import uk.gov.di.ipv.core.fetchsystemsettings.domain.CredentialIssuerConfig;
import uk.gov.di.ipv.core.fetchsystemsettings.domain.FeatureSet;
import uk.gov.di.ipv.core.library.service.AppConfigService;
import uk.gov.di.ipv.core.library.service.ConfigService;

import java.util.HashMap;
import java.util.Map;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

public class FetchSystemSettingsHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {
    private static final Logger LOGGER = LogManager.getLogger();
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final Pattern FEATURE_FLAG_REGEX =
            Pattern.compile("^([a-zA-Z0-9]*)/featureFlags/([a-zA-Z0-9]*)$");
    private static final Pattern CRI_TOGGLE_REGEX =
            Pattern.compile("^([a-zA-Z0-9]*)/credentialIssuers/([a-zA-Z0-9]*)/enabled$");

    final ConfigService configService = getConfigService();

    protected ConfigService getConfigService() {
        return new AppConfigService();
    }

    @Override
    @Logging(clearState = true)
    @Metrics(captureColdStart = true)
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent event, Context context) {
        // Fetch current feature flag statuses
        Map<String, Boolean> featureFlagStatuses =
                configService.getParametersByPrefix("featureFlags").entrySet().stream()
                        .collect(
                                Collectors.toMap(
                                        Map.Entry::getKey,
                                        entry -> Boolean.parseBoolean(entry.getValue())));

        // Fetch current CRI statuses
        Map<String, Boolean> criStatuses =
                configService.getParametersByPrefix("credentialIssuers").entrySet().stream()
                        .filter(entry -> entry.getKey().matches("([a-zA-Z0-9]*)/enabled"))
                        .collect(
                                Collectors.toMap(
                                        entry -> entry.getKey().split("/")[0],
                                        entry -> Boolean.parseBoolean(entry.getValue())));

        // Fetch feature sets
        Map<String, FeatureSet> featureSets = new HashMap<>();
        configService
                .getParametersByPrefix("features")
                .forEach(
                        (key, value) -> {
                            var featureFlagMatcher = FEATURE_FLAG_REGEX.matcher(key);
                            var criToggleMatcher = CRI_TOGGLE_REGEX.matcher(key);

                            // Get feature set
                            var featureSetName =
                                    featureFlagMatcher.matches()
                                            ? featureFlagMatcher.group(1)
                                            : criToggleMatcher.matches()
                                                    ? criToggleMatcher.group(1)
                                                    : null;
                            if (featureSetName != null
                                    && !featureSets.containsKey(featureSetName)) {
                                featureSets.put(
                                        featureSetName,
                                        new FeatureSet(new HashMap<>(), new HashMap<>()));
                            }
                            var featureSet = featureSets.get(featureSetName);

                            // Feature flags
                            if (featureFlagMatcher.matches()) {
                                var featureFlagName = featureFlagMatcher.group(2);
                                featureSet
                                        .featureFlags()
                                        .put(featureFlagName, Boolean.parseBoolean(value));
                            }

                            // CRI status
                            if (criToggleMatcher.matches()) {
                                var criName = criToggleMatcher.group(2);
                                LOGGER.warn(
                                        String.format(
                                                "HELLO %s %s",
                                                criName, featureSet.credentialIssuers()));
                                featureSet
                                        .credentialIssuers()
                                        .put(
                                                criName,
                                                new CredentialIssuerConfig(
                                                        Boolean.parseBoolean(value)));
                            }
                        });

        var results =
                Map.of(
                        "featureFlagStatuses",
                        featureFlagStatuses,
                        "criStatuses",
                        criStatuses,
                        "availableFeatureSets",
                        featureSets);

        try {
            return new APIGatewayProxyResponseEvent()
                    .withStatusCode(200)
                    .withHeaders(Map.of("Content-Type", "application/json"))
                    .withBody(OBJECT_MAPPER.writeValueAsString(results));
        } catch (JsonProcessingException e) {
            LOGGER.error("Unhandled exception", e);
            return new APIGatewayProxyResponseEvent()
                    .withStatusCode(500)
                    .withBody("{\"message\": \"Internal Server Error\"}");
        }
    }
}
