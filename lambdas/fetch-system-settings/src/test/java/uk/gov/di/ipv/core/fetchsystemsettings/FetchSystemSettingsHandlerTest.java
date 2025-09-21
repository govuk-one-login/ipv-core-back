package uk.gov.di.ipv.core.fetchsystemsettings;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.domain.Cri;
import uk.gov.di.ipv.core.library.service.LocalConfigService;
import uk.gov.di.ipv.core.library.testdata.CommonData;

import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

@ExtendWith(MockitoExtension.class)
class FetchSystemSettingsHandlerTest {
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    @Mock private Context mockContext;

    private LocalConfigService configService;
    private FetchSystemSettingsHandler handler;

    @BeforeEach
    void setup() throws Exception {
        var parametersYaml =
                new String(
                        CommonData.class
                                .getResourceAsStream("/test-parameters.yaml")
                                .readAllBytes(),
                        StandardCharsets.UTF_8);
        var secretsYaml =
                new String(
                        CommonData.class.getResourceAsStream("/test-secrets.yaml").readAllBytes(),
                        StandardCharsets.UTF_8);

        configService = new LocalConfigService(parametersYaml, secretsYaml);
        handler = new FetchSystemSettingsHandler(configService);
    }

    @Test
    void handlerShouldReturnSystemSettings() throws Exception {
        // Act
        var response = handler.handleRequest(new APIGatewayProxyRequestEvent(), mockContext);
        var body =
                OBJECT_MAPPER.readValue(
                        response.getBody(),
                        new TypeReference<HashMap<String, Map<String, Object>>>() {});

        var cfg = configService.getConfiguration();
        Map<String, Boolean> expectedFeatureFlags = Map.copyOf(cfg.getFeatureFlags());

        var expectedCriStatuses = new HashMap<String, Object>();
        var issuers = cfg.getCredentialIssuers();
        for (var cri : Cri.values()) {
            var wrapper = issuers.getById(cri.getId());
            if (wrapper != null) {
                expectedCriStatuses.put(cri.getId(), Boolean.parseBoolean(wrapper.getEnabled()));
            }
        }

        // Assert
        assertEquals(200, response.getStatusCode());
        assertEquals(expectedFeatureFlags, body.get("featureFlagStatuses"));
        assertEquals(expectedCriStatuses, body.get("criStatuses"));
    }
}
