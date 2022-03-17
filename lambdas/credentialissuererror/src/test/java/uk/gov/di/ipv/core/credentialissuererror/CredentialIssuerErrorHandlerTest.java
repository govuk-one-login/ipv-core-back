package uk.gov.di.ipv.core.credentialissuererror;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.domain.UserStates;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.ConfigurationService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;

import java.io.IOException;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class CredentialIssuerErrorHandlerTest {

    @Mock private Context mockContext;
    @Mock private IpvSessionService mockIpvSessionService;
    @Mock private ConfigurationService mockConfigurationService;

    private CredentialIssuerErrorHandler credentialIssuerErrorHandler;
    private final ObjectMapper objectMapper = new ObjectMapper();

    @BeforeEach
    void setUp() {
        credentialIssuerErrorHandler =
                new CredentialIssuerErrorHandler(mockIpvSessionService, mockConfigurationService);
    }

    @Test
    void shouldReturnJourneyResponseAndUpdateUserState() throws IOException {
        APIGatewayProxyRequestEvent event =
                createRequestEvent(
                        Map.of(
                                "error", "fgdfhgfh",
                                "error_description", "User is not allowed!",
                                "credential_issuer_id", "ukPassport"),
                        Map.of("ipv-session-id", UUID.randomUUID().toString()));

        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(new IpvSessionItem());

        ArgumentCaptor<IpvSessionItem> sessionArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);

        APIGatewayProxyResponseEvent response =
                credentialIssuerErrorHandler.handleRequest(event, mockContext);

        Map<String, Object> responseBody =
                objectMapper.readValue(response.getBody(), new TypeReference<>() {});
        verify(mockIpvSessionService).updateIpvSession(sessionArgumentCaptor.capture());
        assertEquals(
                UserStates.CRI_ERROR.toString(), sessionArgumentCaptor.getValue().getUserState());
        assertEquals(200, response.getStatusCode());
        assertEquals("/journey/next", responseBody.get("journey"));
    }

    private APIGatewayProxyRequestEvent createRequestEvent(
            Map<String, String> body, Map<String, String> headers) {
        APIGatewayProxyRequestEvent input = new APIGatewayProxyRequestEvent();
        input.setBody(
                body.keySet().stream()
                        .map(key -> key + "=" + body.get(key))
                        .collect(Collectors.joining("&")));
        input.setHeaders(headers);
        return input;
    }
}
