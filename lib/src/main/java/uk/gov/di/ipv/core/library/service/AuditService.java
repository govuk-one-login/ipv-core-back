package uk.gov.di.ipv.core.library.service;

import com.amazonaws.services.sqs.AmazonSQS;
import com.amazonaws.services.sqs.AmazonSQSClientBuilder;
import com.amazonaws.services.sqs.model.SendMessageRequest;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import uk.gov.di.ipv.core.library.auditing.AuditEvent;
import uk.gov.di.ipv.core.library.auditing.AuditEventTypes;
import uk.gov.di.ipv.core.library.auditing.AuditExtensionParams;
import uk.gov.di.ipv.core.library.exceptions.SqsException;

import java.time.Instant;

import static uk.gov.di.ipv.core.library.config.EnvironmentVariable.SQS_AUDIT_EVENT_QUEUE_URL;

public class AuditService {
    private final AmazonSQS sqs;
    private final String queueUrl;

    private static final ObjectMapper objectMapper = new ObjectMapper();

    public AuditService(AmazonSQS sqs, ConfigurationService configurationService) {
        this.sqs = sqs;
        queueUrl = configurationService.getEnvironmentVariable(SQS_AUDIT_EVENT_QUEUE_URL);
    }

    public static AmazonSQS getDefaultSqsClient() {
        return AmazonSQSClientBuilder.defaultClient();
    }

    public void sendAuditEvent(AuditEventTypes eventType) throws SqsException {
        sendAuditEvent(eventType, null);
    }

    public void sendAuditEvent(AuditEventTypes eventType, AuditExtensionParams extensions)
            throws SqsException {
        try {
            SendMessageRequest sendMessageRequest =
                    new SendMessageRequest()
                            .withQueueUrl(queueUrl)
                            .withMessageBody(generateMessageBody(eventType, extensions));

            sqs.sendMessage(sendMessageRequest);
        } catch (JsonProcessingException e) {
            throw new SqsException(e);
        }
    }

    private String generateMessageBody(AuditEventTypes eventType, AuditExtensionParams extensions)
            throws JsonProcessingException {
        AuditEvent auditEvent =
                new AuditEvent((int) Instant.now().getEpochSecond(), eventType, extensions);

        return objectMapper.writeValueAsString(auditEvent);
    }
}
