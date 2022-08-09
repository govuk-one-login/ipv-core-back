package uk.gov.di.ipv.core.credentialissuererror;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.auditing.AuditEventTypes;
import uk.gov.di.ipv.core.library.auditing.AuditEventUser;
import uk.gov.di.ipv.core.library.auditing.AuditExtensionErrorParams;
import uk.gov.di.ipv.core.library.dto.ClientSessionDetailsDto;
import uk.gov.di.ipv.core.library.exceptions.SqsException;
import uk.gov.di.ipv.core.library.helpers.SecureTokenHelper;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.ConfigurationService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;

import java.io.IOException;
import java.util.Map;
import java.util.stream.Collectors;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class CredentialIssuerErrorHandlerTest {

    @Mock private Context mockContext;
    @Mock private ConfigurationService mockConfigurationService;
    @Mock private AuditService mockAuditService;
    @Mock private IpvSessionService mockIpvSessionService;
    @InjectMocks private CredentialIssuerErrorHandler credentialIssuerErrorHandler;

    private final ObjectMapper objectMapper = new ObjectMapper();

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
                        Map.of("ipv-session-id", SecureTokenHelper.generate()));

        ClientSessionDetailsDto clientSessionDetailsDto = new ClientSessionDetailsDto();
        clientSessionDetailsDto.setGovukSigninJourneyId("someGovUkSigninJourneyId");
        clientSessionDetailsDto.setUserId("someUserId");
        IpvSessionItem ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setIpvSessionId("someIpvSessionId");
        ipvSessionItem.setClientSessionDetails(clientSessionDetailsDto);
        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);

        APIGatewayProxyResponseEvent response =
                credentialIssuerErrorHandler.handleRequest(event, mockContext);

        Map<String, Object> responseBody =
                objectMapper.readValue(response.getBody(), new TypeReference<>() {});
        ArgumentCaptor<AuditEventTypes> auditEventType =
                ArgumentCaptor.forClass(AuditEventTypes.class);
        ArgumentCaptor<AuditExtensionErrorParams> auditExtensionParams =
                ArgumentCaptor.forClass(AuditExtensionErrorParams.class);
        ArgumentCaptor<AuditEventUser> auditEventUser =
                ArgumentCaptor.forClass(AuditEventUser.class);

        verify(mockAuditService)
                .sendAuditEvent(
                        auditEventType.capture(),
                        auditExtensionParams.capture(),
                        auditEventUser.capture());
        assertEquals(200, response.getStatusCode());
        assertEquals("/journey/error", responseBody.get("journey"));
        assertEquals(AuditEventTypes.IPV_CRI_AUTH_RESPONSE_RECEIVED, auditEventType.getValue());
        assertEquals(errorCode, auditExtensionParams.getValue().getErrorCode());
        assertEquals(errorDescription, auditExtensionParams.getValue().getErrorDescription());
        assertEquals("someUserId", auditEventUser.getValue().getUserId());
        assertEquals("someIpvSessionId", auditEventUser.getValue().getSessionId());
        assertEquals(
                "someGovUkSigninJourneyId", auditEventUser.getValue().getGovukSigninJourneyId());
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
