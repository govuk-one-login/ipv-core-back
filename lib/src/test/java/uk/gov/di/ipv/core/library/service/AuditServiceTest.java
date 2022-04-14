package uk.gov.di.ipv.core.library.service;

import com.amazonaws.services.sqs.AmazonSQS;
import com.amazonaws.services.sqs.model.SendMessageRequest;
import com.amazonaws.util.Base64;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.auditing.AuditEventProto;
import uk.gov.di.ipv.core.library.auditing.AuditEventTypes;
import uk.gov.di.ipv.core.library.exceptions.SqsException;

import java.io.IOException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class AuditServiceTest {

    @Mock AmazonSQS mockSqs;
    @Mock ConfigurationService mockConfigurationService;

    private final ObjectMapper objectMapper = new ObjectMapper();

    private AuditService auditService;

    @BeforeEach
    void setup() {
        when(mockConfigurationService.getSqsAuditEventQueueUrl())
                .thenReturn("https://example-queue-url");

        auditService = new AuditService(mockSqs, mockConfigurationService);
    }

    @Test
    void shouldSendMessageToSqsQueue() throws IOException, SqsException {
        auditService.sendAuditEvent(AuditEventTypes.IPV_CREDENTIAL_RECEIVED_AND_SIGNATURE_CHECKED);

        ArgumentCaptor<SendMessageRequest> sqsSendMessageRequestCaptor =
                ArgumentCaptor.forClass(SendMessageRequest.class);
        verify(mockSqs).sendMessage(sqsSendMessageRequestCaptor.capture());

        assertEquals(
                "https://example-queue-url", sqsSendMessageRequestCaptor.getValue().getQueueUrl());

        String base64EncodedBody = sqsSendMessageRequestCaptor.getValue().getMessageBody();

        AuditEventProto.AuditEvent messageBody =
                AuditEventProto.AuditEvent.parseFrom(Base64.decode(base64EncodedBody));

        assertEquals(
                AuditEventTypes.IPV_CREDENTIAL_RECEIVED_AND_SIGNATURE_CHECKED.toString(),
                messageBody.getEventName());
    }
}
