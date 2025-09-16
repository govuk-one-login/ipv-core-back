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
import uk.gov.di.ipv.core.library.domain.Cri;
import uk.gov.di.ipv.core.library.service.AppConfigService;
import uk.gov.di.ipv.core.library.service.ConfigService;

import java.util.HashMap;
import java.util.Map;

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
            // Pull the current, feature-overlaid configuration
            var cfg = configService.getConfiguration();

            // Feature flags are already a Map<String, Boolean> in Config
            Map<String, Boolean> featureFlagStatuses =
                    cfg.getFeatureFlags() != null ? cfg.getFeatureFlags() : Map.of();

            // Build CRI enabled/disabled map from typed config
            var criStatuses = new HashMap<String, Boolean>();
            var issuers = cfg.getCredentialIssuers();
            for (var cri : Cri.values()) {
                var wrapper = issuers.getById(cri.getId());
                if (wrapper != null && wrapper.getEnabled() != null) {
                    criStatuses.put(cri.getId(), Boolean.parseBoolean(wrapper.getEnabled()));
                }
            }

            var body =
                    OBJECT_MAPPER.writeValueAsString(
                            Map.of(
                                    "featureFlagStatuses", featureFlagStatuses,
                                    "criStatuses", criStatuses));

            return new APIGatewayProxyResponseEvent()
                    .withStatusCode(200)
                    .withHeaders(Map.of("Content-Type", "application/json"))
                    .withBody(body);

        } catch (JsonProcessingException e) {
            LOGGER.error("Unhandled exception", e);
            return new APIGatewayProxyResponseEvent()
                    .withStatusCode(500)
                    .withBody("{\"message\": \"Internal Server Error\"}");
        }
    }
}
