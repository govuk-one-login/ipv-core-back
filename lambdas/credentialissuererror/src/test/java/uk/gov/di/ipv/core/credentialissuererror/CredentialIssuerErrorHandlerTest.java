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
import uk.gov.di.ipv.core.library.auditing.AuditEventTypes;
import uk.gov.di.ipv.core.library.auditing.AuditExtensionParams;
import uk.gov.di.ipv.core.library.exceptions.SqsException;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.ConfigurationService;

import java.io.IOException;
import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
class CredentialIssuerErrorHandlerTest {

    @Mock private Context mockContext;
    @Mock private ConfigurationService mockConfigurationService;
    @Mock private AuditService mockAuditService;

    private CredentialIssuerErrorHandler credentialIssuerErrorHandler;
    private final ObjectMapper objectMapper = new ObjectMapper();

    @BeforeEach
    void setUp() {
        credentialIssuerErrorHandler =
                new CredentialIssuerErrorHandler(mockConfigurationService, mockAuditService);
    }

    @Test
    void shouldReturnJourneyResponseAndSendAuditLog() throws IOException, SqsException {
        String errorCode = "server_error";
        String errorDescription = "User is not allowed!";
        APIGatewayProxyRequestEvent event =
                createRequestEvent(
                        Map.of(
                                "error", errorCode,
                                "error_description", errorDescription,
                                "credential_issuer_id", "ukPassport"),
                        Map.of("ipv-session-id", UUID.randomUUID().toString()));

        APIGatewayProxyResponseEvent response =
                credentialIssuerErrorHandler.handleRequest(event, mockContext);

        Map<String, Object> responseBody =
                objectMapper.readValue(response.getBody(), new TypeReference<>() {});
        ArgumentCaptor<AuditEventTypes> auditEventType =
                ArgumentCaptor.forClass(AuditEventTypes.class);
        ArgumentCaptor<AuditExtensionParams> auditExtensionParams =
                ArgumentCaptor.forClass(AuditExtensionParams.class);

        verify(mockAuditService)
                .sendAuditEvent(auditEventType.capture(), auditExtensionParams.capture());
        assertEquals(200, response.getStatusCode());
        assertEquals("/journey/error", responseBody.get("journey"));
        assertEquals(AuditEventTypes.IPV_CRI_AUTH_RESPONSE_RECEIVED, auditEventType.getValue());
        assertEquals(errorCode, auditExtensionParams.getValue().getErrorCode());
        assertEquals(errorDescription, auditExtensionParams.getValue().getErrorDescription());
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
