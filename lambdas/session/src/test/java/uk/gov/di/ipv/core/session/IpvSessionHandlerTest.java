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
import uk.gov.di.ipv.core.library.service.ConfigurationService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;

import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class IpvSessionHandlerTest {

    @Mock private Context mockContext;

    @Mock private IpvSessionService mockIpvSessionService;
    @Mock private ConfigurationService mockConfigurationService;

    private final ObjectMapper objectMapper = new ObjectMapper();

    private IpvSessionHandler ipvSessionHandler;

    @BeforeEach
    void setUp() {
        ipvSessionHandler = new IpvSessionHandler(mockIpvSessionService, mockConfigurationService);
    }

    @Test
    void shouldReturnIpvSessionIdWhenProvidedValidRequest() throws JsonProcessingException {
        String ipvSessionId = UUID.randomUUID().toString();
        when(mockIpvSessionService.generateIpvSession(any())).thenReturn(ipvSessionId);

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        Map<String, String> queryStringParameters =
                Map.of(
                        "response_type", "test-response-type",
                        "client_id", "test-client",
                        "redirect_uri", "https://example.com",
                        "scope", "test-scope",
                        "state", "test-state");
        event.setQueryStringParameters(queryStringParameters);

        APIGatewayProxyResponseEvent response = ipvSessionHandler.handleRequest(event, mockContext);

        Map<String, Object> responseBody =
                objectMapper.readValue(response.getBody(), new TypeReference<>() {});

        assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        assertEquals(ipvSessionId, responseBody.get("ipvSessionId"));
    }

    @Test
    void shouldReturn400IfMissingQueryStringParameters() throws JsonProcessingException {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();

        APIGatewayProxyResponseEvent response = ipvSessionHandler.handleRequest(event, mockContext);

        Map<String, Object> responseBody =
                objectMapper.readValue(response.getBody(), new TypeReference<>() {});

        assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        assertEquals(ErrorResponse.MISSING_QUERY_PARAMETERS.getCode(), responseBody.get("code"));
        assertEquals(
                ErrorResponse.MISSING_QUERY_PARAMETERS.getMessage(), responseBody.get("message"));
    }

    @Test
    void shouldReturn400IfMissingResponseTypeParameter() throws JsonProcessingException {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();

        Map<String, String> queryStringParameters =
                Map.of(
                        "client_id", "test-client",
                        "redirect_uri", "https://example.com",
                        "scope", "test-scope",
                        "state", "test-state");
        event.setQueryStringParameters(queryStringParameters);

        APIGatewayProxyResponseEvent response = ipvSessionHandler.handleRequest(event, mockContext);

        Map<String, Object> responseBody =
                objectMapper.readValue(response.getBody(), new TypeReference<>() {});

        assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        assertEquals(ErrorResponse.MISSING_QUERY_PARAMETERS.getCode(), responseBody.get("code"));
        assertEquals(
                ErrorResponse.MISSING_QUERY_PARAMETERS.getMessage(), responseBody.get("message"));
    }

    @Test
    void shouldReturn400IfMissingClientIdParameter() throws JsonProcessingException {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();

        Map<String, String> queryStringParameters =
                Map.of(
                        "responseType", "test-response-type",
                        "redirect_uri", "https://example.com",
                        "scope", "test-scope",
                        "state", "test-state");
        event.setQueryStringParameters(queryStringParameters);

        APIGatewayProxyResponseEvent response = ipvSessionHandler.handleRequest(event, mockContext);

        Map<String, Object> responseBody =
                objectMapper.readValue(response.getBody(), new TypeReference<>() {});

        assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        assertEquals(ErrorResponse.MISSING_QUERY_PARAMETERS.getCode(), responseBody.get("code"));
        assertEquals(
                ErrorResponse.MISSING_QUERY_PARAMETERS.getMessage(), responseBody.get("message"));
    }

    @Test
    void shouldReturn400IfMissingRedirectUriParameter() throws JsonProcessingException {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();

        Map<String, String> queryStringParameters =
                Map.of(
                        "responseType", "test-response-type",
                        "client_id", "test-client",
                        "scope", "test-scope",
                        "state", "test-state");
        event.setQueryStringParameters(queryStringParameters);

        APIGatewayProxyResponseEvent response = ipvSessionHandler.handleRequest(event, mockContext);

        Map<String, Object> responseBody =
                objectMapper.readValue(response.getBody(), new TypeReference<>() {});

        assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        assertEquals(ErrorResponse.MISSING_QUERY_PARAMETERS.getCode(), responseBody.get("code"));
        assertEquals(
                ErrorResponse.MISSING_QUERY_PARAMETERS.getMessage(), responseBody.get("message"));
    }

    @Test
    void shouldReturn400IfMissingScopeParameter() throws JsonProcessingException {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();

        Map<String, String> queryStringParameters =
                Map.of(
                        "responseType", "test-response-type",
                        "client_id", "test-client",
                        "redirect_uri", "https://example.com",
                        "state", "test-state");
        event.setQueryStringParameters(queryStringParameters);

        APIGatewayProxyResponseEvent response = ipvSessionHandler.handleRequest(event, mockContext);

        Map<String, Object> responseBody =
                objectMapper.readValue(response.getBody(), new TypeReference<>() {});

        assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        assertEquals(ErrorResponse.MISSING_QUERY_PARAMETERS.getCode(), responseBody.get("code"));
        assertEquals(
                ErrorResponse.MISSING_QUERY_PARAMETERS.getMessage(), responseBody.get("message"));
    }

    @Test
    void shouldReturn400IfMissingStateParameter() throws JsonProcessingException {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();

        Map<String, String> queryStringParameters =
                Map.of(
                        "responseType", "test-response-type",
                        "client_id", "test-client",
                        "redirect_uri", "https://example.com",
                        "scope", "test-scope");
        event.setQueryStringParameters(queryStringParameters);

        APIGatewayProxyResponseEvent response = ipvSessionHandler.handleRequest(event, mockContext);

        Map<String, Object> responseBody =
                objectMapper.readValue(response.getBody(), new TypeReference<>() {});

        assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        assertEquals(ErrorResponse.MISSING_QUERY_PARAMETERS.getCode(), responseBody.get("code"));
        assertEquals(
                ErrorResponse.MISSING_QUERY_PARAMETERS.getMessage(), responseBody.get("message"));
    }
}
