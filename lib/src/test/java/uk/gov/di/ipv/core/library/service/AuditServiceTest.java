package uk.gov.di.ipv.core.library.service;

import com.amazonaws.services.sqs.AmazonSQS;
import com.amazonaws.services.sqs.model.SendMessageRequest;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.auditing.AuditEvent;
import uk.gov.di.ipv.core.library.auditing.AuditEventTypes;
import uk.gov.di.ipv.core.library.auditing.AuditExtensionParams;
import uk.gov.di.ipv.core.library.exceptions.SqsException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.config.EnvironmentVariable.SQS_AUDIT_EVENT_QUEUE_URL;

@ExtendWith(MockitoExtension.class)
class AuditServiceTest {

    @Mock AmazonSQS mockSqs;
    @Mock ConfigurationService mockConfigurationService;

    private final ObjectMapper objectMapper = new ObjectMapper();

    private AuditService auditService;

    @BeforeEach
    void setup() {
        when(mockConfigurationService.getEnvironmentVariable(SQS_AUDIT_EVENT_QUEUE_URL))
                .thenReturn("https://example-queue-url");

        auditService = new AuditService(mockSqs, mockConfigurationService);
    }

    @Test
    void shouldSendMessageToSqsQueue() throws JsonProcessingException, SqsException {
        auditService.sendAuditEvent(
                AuditEventTypes.IPV_CREDENTIAL_RECEIVED_AND_SIGNATURE_CHECKED, null);

        ArgumentCaptor<SendMessageRequest> sqsSendMessageRequestCaptor =
                ArgumentCaptor.forClass(SendMessageRequest.class);
        verify(mockSqs).sendMessage(sqsSendMessageRequestCaptor.capture());

        assertEquals(
                "https://example-queue-url", sqsSendMessageRequestCaptor.getValue().getQueueUrl());

        AuditEvent messageBody =
                objectMapper.readValue(
                        sqsSendMessageRequestCaptor.getValue().getMessageBody(), AuditEvent.class);
        assertEquals(
                AuditEventTypes.IPV_CREDENTIAL_RECEIVED_AND_SIGNATURE_CHECKED,
                messageBody.getEvent());
    }

    @Test
    void shouldSendMessageToSqsQueueWithExtensions() throws JsonProcessingException, SqsException {
        String errorCode = "server_error";
        String errorDescription = "Test error";
        AuditExtensionParams extensions =
                new AuditExtensionParams.Builder()
                        .setErrorCode(errorCode)
                        .setErrorDescription(errorDescription)
                        .build();
        auditService.sendAuditEvent(
                AuditEventTypes.IPV_CREDENTIAL_RECEIVED_AND_SIGNATURE_CHECKED, extensions);

        ArgumentCaptor<SendMessageRequest> sqsSendMessageRequestCaptor =
                ArgumentCaptor.forClass(SendMessageRequest.class);
        verify(mockSqs).sendMessage(sqsSendMessageRequestCaptor.capture());

        assertEquals(
                "https://example-queue-url", sqsSendMessageRequestCaptor.getValue().getQueueUrl());

        AuditEvent messageBody =
                objectMapper.readValue(
                        sqsSendMessageRequestCaptor.getValue().getMessageBody(), AuditEvent.class);
        assertEquals(
                AuditEventTypes.IPV_CREDENTIAL_RECEIVED_AND_SIGNATURE_CHECKED,
                messageBody.getEvent());
        assertEquals(extensions.getErrorCode(), messageBody.getExtensions().getErrorCode());
        assertEquals(
                extensions.getErrorDescription(),
                messageBody.getExtensions().getErrorDescription());
    }
}
