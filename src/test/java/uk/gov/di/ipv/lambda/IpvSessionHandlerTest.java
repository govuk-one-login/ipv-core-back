package uk.gov.di.ipv.lambda;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.service.IpvSessionService;

import java.time.Instant;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class IpvSessionHandlerTest {

    @Mock
    private Context mockContext;

    @Mock
    private IpvSessionService mockIpvSessionService;

    private final ObjectMapper objectMapper = new ObjectMapper();
    private final String testUserId = UUID.randomUUID().toString();

    private IpvSessionHandler ipvSessionHandler;

    @BeforeEach
    void setUp() {
        ipvSessionHandler = new IpvSessionHandler(mockIpvSessionService);
    }

    @Test
    void shouldReturnIpvSessionIdWhenProvidedValidRequest() throws JsonProcessingException {
        IpvSessionItem ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setIpvSessionId(UUID.randomUUID().toString());
        ipvSessionItem.setCreationDateTime(Instant.now().toString());

        when(mockIpvSessionService.generateIpvSession()).thenReturn(ipvSessionItem);

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        String requestBody = "userId=" + testUserId;
        event.setBody(requestBody);

        APIGatewayProxyResponseEvent response = ipvSessionHandler.handleRequest(event, mockContext);

        Map<String, Object> responseBody = objectMapper.readValue(response.getBody(), Map.class);

        assertEquals(200, response.getStatusCode());
        assertEquals(ipvSessionItem.getIpvSessionId(), responseBody.get("ipvSessionId"));
        assertEquals(ipvSessionItem.getCreationDateTime().toString(), responseBody.get("creationDateTime"));
    }
}
