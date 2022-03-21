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
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.dto.ClientSessionDetailsDto;
import uk.gov.di.ipv.core.library.service.ConfigurationService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;

import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class IpvSessionStartHandlerTest {

    @Mock private Context mockContext;

    @Mock private IpvSessionService mockIpvSessionService;
    @Mock private ConfigurationService mockConfigurationService;

    private final ObjectMapper objectMapper = new ObjectMapper();

    private IpvSessionStartHandler ipvSessionStartHandler;

    @BeforeEach
    void setUp() {
        ipvSessionStartHandler =
                new IpvSessionStartHandler(mockIpvSessionService, mockConfigurationService);
    }

    @Test
    void shouldReturnIpvSessionIdWhenProvidedValidRequest() throws JsonProcessingException {
        String ipvSessionId = UUID.randomUUID().toString();
        when(mockIpvSessionService.generateIpvSession(any())).thenReturn(ipvSessionId);

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        ClientSessionDetailsDto clientSessionDetailsDto =
                new ClientSessionDetailsDto(
                        "test-response-type",
                        "test-client",
                        "https://example.com",
                        "test-scope",
                        "test-state",
                        false);
        event.setBody(objectMapper.writeValueAsString(clientSessionDetailsDto));

        APIGatewayProxyResponseEvent response =
                ipvSessionStartHandler.handleRequest(event, mockContext);

        Map<String, Object> responseBody =
                objectMapper.readValue(response.getBody(), new TypeReference<>() {});

        assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        assertEquals(ipvSessionId, responseBody.get("ipvSessionId"));
    }

    @Test
    void shouldReturn400IfMissingBody() throws JsonProcessingException {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();

        APIGatewayProxyResponseEvent response =
                ipvSessionStartHandler.handleRequest(event, mockContext);

        Map<String, Object> responseBody =
                objectMapper.readValue(response.getBody(), new TypeReference<>() {});

        assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        assertEquals(ErrorResponse.INVALID_SESSION_REQUEST.getCode(), responseBody.get("code"));
        assertEquals(
                ErrorResponse.INVALID_SESSION_REQUEST.getMessage(), responseBody.get("message"));
    }

    @Test
    void shouldReturn400IfInvalidBody() throws JsonProcessingException {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setBody("invalid-body");

        APIGatewayProxyResponseEvent response =
                ipvSessionStartHandler.handleRequest(event, mockContext);
        Map<String, Object> responseBody =
                objectMapper.readValue(response.getBody(), new TypeReference<>() {});

        assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        assertEquals(ErrorResponse.INVALID_SESSION_REQUEST.getCode(), responseBody.get("code"));
        assertEquals(
                ErrorResponse.INVALID_SESSION_REQUEST.getMessage(), responseBody.get("message"));
    }

    @Test
    void shouldReturn400IfMissingResponseTypeParameter() throws JsonProcessingException {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();

        ClientSessionDetailsDto clientSessionDetailsDto =
                new ClientSessionDetailsDto(
                        null,
                        "test-client-id",
                        "https://example.com",
                        "test-scope",
                        "test-state",
                        false);
        event.setBody(objectMapper.writeValueAsString(clientSessionDetailsDto));

        APIGatewayProxyResponseEvent response =
                ipvSessionStartHandler.handleRequest(event, mockContext);

        Map<String, Object> responseBody =
                objectMapper.readValue(response.getBody(), new TypeReference<>() {});

        assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        assertEquals(ErrorResponse.INVALID_SESSION_REQUEST.getCode(), responseBody.get("code"));
        assertEquals(
                ErrorResponse.INVALID_SESSION_REQUEST.getMessage(), responseBody.get("message"));
    }

    @Test
    void shouldReturn400IfMissingClientIdParameter() throws JsonProcessingException {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();

        ClientSessionDetailsDto clientSessionDetailsDto =
                new ClientSessionDetailsDto(
                        "test-response-type",
                        null,
                        "https://example.com",
                        "test-scope",
                        "test-state",
                        false);
        event.setBody(objectMapper.writeValueAsString(clientSessionDetailsDto));

        APIGatewayProxyResponseEvent response =
                ipvSessionStartHandler.handleRequest(event, mockContext);

        Map<String, Object> responseBody =
                objectMapper.readValue(response.getBody(), new TypeReference<>() {});

        assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        assertEquals(ErrorResponse.INVALID_SESSION_REQUEST.getCode(), responseBody.get("code"));
        assertEquals(
                ErrorResponse.INVALID_SESSION_REQUEST.getMessage(), responseBody.get("message"));
    }

    @Test
    void shouldReturn400IfMissingRedirectUriParameter() throws JsonProcessingException {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();

        ClientSessionDetailsDto clientSessionDetailsDto =
                new ClientSessionDetailsDto(
                        "test-response-type",
                        "test-client-id",
                        null,
                        "test-scope",
                        "test-state",
                        false);
        event.setBody(objectMapper.writeValueAsString(clientSessionDetailsDto));

        APIGatewayProxyResponseEvent response =
                ipvSessionStartHandler.handleRequest(event, mockContext);

        Map<String, Object> responseBody =
                objectMapper.readValue(response.getBody(), new TypeReference<>() {});

        assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        assertEquals(ErrorResponse.INVALID_SESSION_REQUEST.getCode(), responseBody.get("code"));
        assertEquals(
                ErrorResponse.INVALID_SESSION_REQUEST.getMessage(), responseBody.get("message"));
    }

    @Test
    void shouldReturn400IfMissingScopeParameter() throws JsonProcessingException {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();

        ClientSessionDetailsDto clientSessionDetailsDto =
                new ClientSessionDetailsDto(
                        "test-response-type",
                        "test-client-id",
                        "https://example.com",
                        null,
                        "test-state",
                        false);
        event.setBody(objectMapper.writeValueAsString(clientSessionDetailsDto));

        APIGatewayProxyResponseEvent response =
                ipvSessionStartHandler.handleRequest(event, mockContext);

        Map<String, Object> responseBody =
                objectMapper.readValue(response.getBody(), new TypeReference<>() {});

        assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        assertEquals(ErrorResponse.INVALID_SESSION_REQUEST.getCode(), responseBody.get("code"));
        assertEquals(
                ErrorResponse.INVALID_SESSION_REQUEST.getMessage(), responseBody.get("message"));
    }

    @Test
    void shouldReturn400IfMissingStateParameter() throws JsonProcessingException {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();

        ClientSessionDetailsDto clientSessionDetailsDto =
                new ClientSessionDetailsDto(
                        "test-response-type",
                        "test-client-id",
                        "https://example.com",
                        "test-scope",
                        null,
                        false);
        event.setBody(objectMapper.writeValueAsString(clientSessionDetailsDto));

        APIGatewayProxyResponseEvent response =
                ipvSessionStartHandler.handleRequest(event, mockContext);

        Map<String, Object> responseBody =
                objectMapper.readValue(response.getBody(), new TypeReference<>() {});

        assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        assertEquals(ErrorResponse.INVALID_SESSION_REQUEST.getCode(), responseBody.get("code"));
        assertEquals(
                ErrorResponse.INVALID_SESSION_REQUEST.getMessage(), responseBody.get("message"));
    }
}
