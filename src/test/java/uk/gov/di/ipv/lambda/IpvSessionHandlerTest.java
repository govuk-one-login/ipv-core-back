package uk.gov.di.ipv.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.http.HttpStatus;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.service.IpvSessionService;
import uk.org.webcompere.systemstubs.environment.EnvironmentVariables;
import uk.org.webcompere.systemstubs.jupiter.SystemStub;
import uk.org.webcompere.systemstubs.jupiter.SystemStubsExtension;

import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.service.ConfigurationService.IS_LOCAL;

@ExtendWith(MockitoExtension.class)
@ExtendWith(SystemStubsExtension.class)
class IpvSessionHandlerTest {

    @SystemStub private EnvironmentVariables environmentVariables;

    @Mock private Context mockContext;

    @Mock private IpvSessionService mockIpvSessionService;

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final String testUserId = UUID.randomUUID().toString();

    private IpvSessionHandler ipvSessionHandler;

    @BeforeEach
    void setUp() {
        ipvSessionHandler = new IpvSessionHandler(mockIpvSessionService);
    }

    @Test
    void noArgsConstructor() {
        environmentVariables.set(IS_LOCAL, "true");
        assertDoesNotThrow(() -> new IpvSessionHandler());
    }

    @Test
    void shouldReturnIpvSessionIdWhenProvidedValidRequest() throws JsonProcessingException {
        String ipvSessionId = UUID.randomUUID().toString();
        when(mockIpvSessionService.generateIpvSession()).thenReturn(ipvSessionId);

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        APIGatewayProxyResponseEvent response = ipvSessionHandler.handleRequest(event, mockContext);

        Map<String, Object> responseBody = objectMapper.readValue(response.getBody(), Map.class);

        assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        assertEquals(ipvSessionId, responseBody.get("ipvSessionId"));
    }
}
