package uk.gov.di.ipv.core.session;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.http.HttpStatus;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.service.IpvSessionService;

import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class IpvSessionHandlerTest {

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
  void shouldReturnIpvSessionIdWhenProvidedValidRequest() throws JsonProcessingException {
    String ipvSessionId = UUID.randomUUID().toString();
    when(mockIpvSessionService.generateIpvSession()).thenReturn(ipvSessionId);

    APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
    APIGatewayProxyResponseEvent response = ipvSessionHandler.handleRequest(event, mockContext);

    Map<String, Object> responseBody =
        objectMapper.readValue(response.getBody(), new TypeReference<>() {});

    assertEquals(HttpStatus.SC_OK, response.getStatusCode());
    assertEquals(ipvSessionId, responseBody.get("ipvSessionId"));
  }
}
