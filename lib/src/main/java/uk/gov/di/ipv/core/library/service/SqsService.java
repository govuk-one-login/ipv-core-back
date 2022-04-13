package uk.gov.di.ipv.core.library.service;

import com.amazonaws.services.sqs.AmazonSQS;
import com.amazonaws.services.sqs.AmazonSQSClientBuilder;
import com.amazonaws.services.sqs.model.SendMessageRequest;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import uk.gov.di.ipv.core.library.auditing.AuditEvent;
import uk.gov.di.ipv.core.library.auditing.AuditEventTypes;
import uk.gov.di.ipv.core.library.exceptions.SqsException;

import java.time.Instant;

public class SqsService {
    private final AmazonSQS sqs;
    private final String queueUrl;

    public SqsService(AmazonSQS sqs, ConfigurationService configurationService) {
        this.sqs = sqs;
        queueUrl = configurationService.getSqsAuditEventQueueUrl();
    }

    public static AmazonSQS getDefaultSqsClient() {
        return AmazonSQSClientBuilder.defaultClient();
    }

    public void sendAuditEvent(AuditEventTypes eventType) throws SqsException {
        try {
            SendMessageRequest sendMessageRequest =
                    new SendMessageRequest()
                            .withQueueUrl(queueUrl)
                            .withMessageBody(generateMessageBody(eventType));

            sqs.sendMessage(sendMessageRequest);
        } catch (JsonProcessingException e) {
            throw new SqsException(e);
        }
    }

    private String generateMessageBody(AuditEventTypes eventType) throws JsonProcessingException {
        AuditEvent auditEvent =
                new AuditEvent(Instant.now().getEpochSecond(), eventType.toString());

        ObjectMapper objectMapper = new ObjectMapper();
        return objectMapper.writeValueAsString(auditEvent);
    }
}
