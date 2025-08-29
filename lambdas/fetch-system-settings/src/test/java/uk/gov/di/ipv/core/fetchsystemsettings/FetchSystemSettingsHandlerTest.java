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
import uk.gov.di.ipv.core.library.service.ConfigService;
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
                new FetchSystemSettingsHandler() {
                    @Override
                    protected ConfigService getConfigService() {
                        return new LocalConfigService(parametersYaml, secretsYaml);
                    }
                };
    }

    @Test
    void handlerShouldReturnJourneyTransitions() throws JsonProcessingException {
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
        assertEquals(
                OBJECT_MAPPER.readValue(
                        """
                            {
                                "drivingLicenceTest":          {"featureFlags": {},                                     "credentialIssuers": {"drivingLicence": {"enabled": false}}},
                                "disableStrategicApp":         {"featureFlags": {"strategicAppEnabled": false},         "credentialIssuers": {}},
                                "ticfDisabled":                {"featureFlags": {},                                     "credentialIssuers": {"ticf": {"enabled": false}}},
                                "strategicApp":                {"featureFlags": {"strategicAppEnabled": true},          "credentialIssuers": {}},
                                "accountInterventions":        {"featureFlags": {"accountInterventionsEnabled": true},  "credentialIssuers": {}},
                                "dcmawOffTest":                {"featureFlags": {},                                     "credentialIssuers": {"dcmaw": {"enabled": false}}},
                                "f2fDisabled":                 {"featureFlags": {},                                     "credentialIssuers": {"f2f": {"enabled": false}}},
                                "dwpKbvTest":                  {"featureFlags": {},                                     "credentialIssuers": {"dwpKbv": {"enabled": true}}},
                                "dwpKbvDisabled":              {"featureFlags": {},                                     "credentialIssuers": {"dwpKbv": {"enabled": false}}},
                                "ticfCriBeta":                 {"featureFlags": {},                                     "credentialIssuers": {"ticf": {"enabled": true}}},
                                "p1Journeys":                  {"featureFlags": {"p1JourneysEnabled": true},            "credentialIssuers": {}},
                                "disableAccountInterventions": {"featureFlags": {"accountInterventionsEnabled": false}, "credentialIssuers": {}},
                                "mfaReset":                    {"featureFlags": {"mfaResetEnabled": true},              "credentialIssuers": {}},
                                "clearUsersIdentity":          {"featureFlags": {"resetIdentity": true},                "credentialIssuers": {}},
                                "pendingF2FResetEnabled":      {"featureFlags": {"pendingF2FResetEnabled": true},       "credentialIssuers": {}},
                                "storedIdentityService":       {"featureFlags": {"storedIdentityServiceEnabled": true}, "credentialIssuers": {}},
                                "bavDisabled":                 {"featureFlags": {},                                     "credentialIssuers": {"bav": {"enabled": false}}}
                            }
                        """,
                        new TypeReference<>() {}),
                body.get("availableFeatureSets"));
    }
}
