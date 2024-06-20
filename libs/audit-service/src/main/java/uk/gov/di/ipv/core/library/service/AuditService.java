package uk.gov.di.ipv.core.library.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import software.amazon.awssdk.http.crt.AwsCrtHttpClient;
import software.amazon.awssdk.services.sqs.SqsClient;
import software.amazon.awssdk.services.sqs.model.SendMessageRequest;
import uk.gov.di.ipv.core.library.auditing.AuditEvent;
import uk.gov.di.ipv.core.library.exceptions.SqsException;

import static software.amazon.awssdk.regions.Region.EU_WEST_2;
import static uk.gov.di.ipv.core.library.config.EnvironmentVariable.SQS_AUDIT_EVENT_QUEUE_URL;

public class AuditService {
    private final SqsClient sqs;
    private final String queueUrl;
    private final ObjectMapper objectMapper;

    public AuditService(SqsClient sqs, ConfigService configService) {
        this.sqs = sqs;
        this.queueUrl = configService.getEnvironmentVariable(SQS_AUDIT_EVENT_QUEUE_URL);
        this.objectMapper = new ObjectMapper();
    }

    public AuditService(SqsClient sqs, ConfigService configService, ObjectMapper objectMapper) {
        this.sqs = sqs;
        this.queueUrl = configService.getEnvironmentVariable(SQS_AUDIT_EVENT_QUEUE_URL);
        this.objectMapper = objectMapper;
    }

    public static SqsClient getSqsClient() {
        return SqsClient.builder()
                .region(EU_WEST_2)
                .httpClientBuilder(AwsCrtHttpClient.builder())
                .build();
    }

    public void sendAuditEvent(AuditEvent auditEvent) throws SqsException {
        try {
            sqs.sendMessage(
                    SendMessageRequest.builder()
                            .queueUrl(queueUrl)
                            .messageBody(objectMapper.writeValueAsString(auditEvent))
                            .build());
        } catch (JsonProcessingException e) {
            throw new SqsException(e);
        }
    }
}
