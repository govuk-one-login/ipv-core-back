package uk.gov.di.ipv.core.library.service;

import com.amazonaws.services.sqs.AmazonSQS;
import com.amazonaws.services.sqs.AmazonSQSClientBuilder;
import com.amazonaws.services.sqs.model.SendMessageRequest;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import uk.gov.di.ipv.core.library.auditing.AuditEvent;
import uk.gov.di.ipv.core.library.auditing.AuditEventTypes;
import uk.gov.di.ipv.core.library.auditing.AuditEventUser;
import uk.gov.di.ipv.core.library.auditing.AuditExtensions;
import uk.gov.di.ipv.core.library.exceptions.SqsException;

import static uk.gov.di.ipv.core.library.config.EnvironmentVariable.SQS_AUDIT_EVENT_QUEUE_URL;

public class AuditService {
    private final AmazonSQS sqs;
    private final String queueUrl;

    private ObjectMapper objectMapper;

    public AuditService(AmazonSQS sqs, ConfigurationService configurationService) {
        this.sqs = sqs;
        this.queueUrl = configurationService.getEnvironmentVariable(SQS_AUDIT_EVENT_QUEUE_URL);
        this.objectMapper = new ObjectMapper();
    }

    public AuditService(
            AmazonSQS sqs, ConfigurationService configurationService, ObjectMapper objectMapper) {
        this.sqs = sqs;
        this.queueUrl = configurationService.getEnvironmentVariable(SQS_AUDIT_EVENT_QUEUE_URL);
        this.objectMapper = objectMapper;
    }

    public static AmazonSQS getDefaultSqsClient() {
        return AmazonSQSClientBuilder.defaultClient();
    }

    public void sendAuditEvent(AuditEventTypes eventType) throws SqsException {
        sendAuditEvent(eventType, null, null);
    }

    public void sendAuditEvent(AuditEventTypes eventType, AuditExtensions extensions)
            throws SqsException {
        sendAuditEvent(eventType, extensions, null);
    }

    public void sendAuditEvent(
            AuditEventTypes eventType, AuditExtensions extensions, AuditEventUser user)
            throws SqsException {
        AuditEvent auditEvent = new AuditEvent(eventType, null, user, extensions);
        sendAuditEvent(auditEvent);
    }

    public void sendAuditEvent(AuditEvent auditEvent) throws SqsException {
        try {
            SendMessageRequest sendMessageRequest =
                    new SendMessageRequest()
                            .withQueueUrl(queueUrl)
                            .withMessageBody(objectMapper.writeValueAsString(auditEvent));

            sqs.sendMessage(sendMessageRequest);
        } catch (JsonProcessingException e) {
            throw new SqsException(e);
        }
    }
}
