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
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.service.AppConfigService;
import uk.gov.di.ipv.core.library.service.ConfigService;

import java.util.Map;
import java.util.stream.Collectors;

public class FetchSystemSettingsHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {
    private static final Logger LOGGER = LogManager.getLogger();
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private final ConfigService configService;

    @ExcludeFromGeneratedCoverageReport
    public FetchSystemSettingsHandler() {
        this.configService = new AppConfigService();
    }

    @ExcludeFromGeneratedCoverageReport
    public FetchSystemSettingsHandler(ConfigService configService) {
        this.configService = configService;
    }

    @Override
    @Logging(clearState = true)
    @Metrics(captureColdStart = true)
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent event, Context context) {
        try {
            // Fetch current feature flag statuses
            Map<String, Boolean> featureFlagStatuses =
                    configService.getParametersByPrefix("featureFlags").entrySet().stream()
                            .collect(
                                    Collectors.toMap(
                                            Map.Entry::getKey,
                                            entry -> Boolean.parseBoolean(entry.getValue())));
            LOGGER.error("Fetched feature flag statuses: {}", featureFlagStatuses);

            // Fetch current CRI statuses
            Map<String, Boolean> criStatuses =
                    configService.getParametersByPrefix("credentialIssuers").entrySet().stream()
                            .filter(entry -> entry.getKey().matches("([a-zA-Z0-9]*)/enabled"))
                            .collect(
                                    Collectors.toMap(
                                            entry -> entry.getKey().split("/")[0],
                                            entry -> Boolean.parseBoolean(entry.getValue())));
            LOGGER.error("Fetched credential issuer statuses: {}", criStatuses);
            return new APIGatewayProxyResponseEvent()
                    .withStatusCode(200)
                    .withHeaders(Map.of("Content-Type", "application/json"))
                    .withBody(
                            OBJECT_MAPPER.writeValueAsString(
                                    Map.of(
                                            "featureFlagStatuses",
                                            featureFlagStatuses,
                                            "criStatuses",
                                            criStatuses)));
        } catch (JsonProcessingException e) {
            LOGGER.error("Unhandled exception", e);
            return new APIGatewayProxyResponseEvent()
                    .withStatusCode(500)
                    .withBody("{\"message\": \"Internal Server Error\"}");
        }
    }
}
