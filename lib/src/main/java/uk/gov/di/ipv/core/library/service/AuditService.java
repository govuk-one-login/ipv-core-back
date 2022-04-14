package uk.gov.di.ipv.core.library.service;

import com.amazonaws.services.sqs.AmazonSQS;
import com.amazonaws.services.sqs.AmazonSQSClientBuilder;
import com.amazonaws.services.sqs.model.SendMessageRequest;
import uk.gov.di.ipv.core.library.auditing.AuditEventProto;
import uk.gov.di.ipv.core.library.auditing.AuditEventTypes;

import java.time.Instant;
import java.util.Base64;

public class AuditService {
    private final AmazonSQS sqs;
    private final String queueUrl;

    public AuditService(AmazonSQS sqs, ConfigurationService configurationService) {
        this.sqs = sqs;
        queueUrl = configurationService.getSqsAuditEventQueueUrl();
    }

    public static AmazonSQS getDefaultSqsClient() {
        return AmazonSQSClientBuilder.defaultClient();
    }

    public void sendAuditEvent(AuditEventTypes eventType) {
        SendMessageRequest sendMessageRequest =
                new SendMessageRequest()
                        .withQueueUrl(queueUrl)
                        .withMessageBody(generateMessageBody(eventType));

        sqs.sendMessage(sendMessageRequest);
    }

    private String generateMessageBody(AuditEventTypes eventType) {
        AuditEventProto.AuditEvent auditEvent =
                AuditEventProto.AuditEvent.newBuilder()
                        .setTimestamp((int) Instant.now().getEpochSecond())
                        .setEventName(eventType.toString())
                        .build();

        return Base64.getEncoder().encodeToString(auditEvent.toByteArray());
    }
}
