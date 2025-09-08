package uk.gov.di.ipv.core.fetchsystemsettings;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.service.LocalConfigService;
import uk.gov.di.ipv.core.library.testdata.CommonData;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

@ExtendWith(MockitoExtension.class)
class FetchSystemSettingsHandlerTest {
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    @Mock private Context mockContext;
    private FetchSystemSettingsHandler handler;

    @BeforeEach
    void setup() throws IOException {
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

        handler =
                new FetchSystemSettingsHandler(new LocalConfigService(parametersYaml, secretsYaml));
    }

    @Test
    void handlerShouldReturnSystemSettings() throws JsonProcessingException {
        // Act
        var response = handler.handleRequest(new APIGatewayProxyRequestEvent(), mockContext);
        HashMap<String, Map<String, Object>> body =
                OBJECT_MAPPER.readValue(response.getBody(), new TypeReference<>() {});

        // Assert
        assertEquals(
                OBJECT_MAPPER.readValue(
                        """
                        {
                            "kidJarHeaderEnabled": true,
                            "strategicAppEnabled": true,
                            "drivingLicenceAuthCheck": true,
                            "mfaResetEnabled": true,
                            "resetIdentity": false,
                            "repeatFraudCheckEnabled": true,
                            "sqsAsync": true,
                            "p1JourneysEnabled": true,
                            "storedIdentityServiceEnabled": false,
                            "accountInterventionsEnabled": true,
                            "pendingF2FResetEnabled": false,
                            "parseVcClasses": true
                        }
                    """,
                        new TypeReference<>() {}),
                body.get("featureFlagStatuses"));
        assertEquals(
                OBJECT_MAPPER.readValue(
                        """
                            {
                                "address": true,
                                "ukPassport": true,
                                "dcmawAsync": false,
                                "drivingLicence": true,
                                "dwpKbv": false,
                                "dcmaw": true,
                                "ticf": true,
                                "nino": false,
                                "bav": true,
                                "fraud": true,
                                "f2f": true,
                                "claimedIdentity": true,
                                "experianKbv": true
                            }
                        """,
                        new TypeReference<>() {}),
                body.get("criStatuses"));
    }
}
