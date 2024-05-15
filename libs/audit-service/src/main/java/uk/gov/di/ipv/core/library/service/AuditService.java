package uk.gov.di.ipv.core.library.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import software.amazon.awssdk.http.urlconnection.UrlConnectionHttpClient;
import software.amazon.awssdk.services.sqs.SqsClient;
import software.amazon.awssdk.services.sqs.model.SendMessageRequest;
import uk.gov.di.ipv.core.library.auditing.AuditEvent;
import uk.gov.di.ipv.core.library.auditing.restricted.AuditRestrictedDeviceInformation;
import uk.gov.di.ipv.core.library.config.CoreFeatureFlag;
import uk.gov.di.ipv.core.library.exceptions.SqsException;

import static software.amazon.awssdk.regions.Region.EU_WEST_2;
import static uk.gov.di.ipv.core.library.config.EnvironmentVariable.SQS_AUDIT_EVENT_QUEUE_URL;

public class AuditService {
    private final SqsClient sqs;
    private final String queueUrl;
    private final ObjectMapper objectMapper;
    private final ConfigService configService;

    public AuditService(SqsClient sqs, ConfigService configService) {
        this.sqs = sqs;
        this.queueUrl = configService.getEnvironmentVariable(SQS_AUDIT_EVENT_QUEUE_URL);
        this.objectMapper = new ObjectMapper();
        this.configService = configService;
    }

    public AuditService(SqsClient sqs, ConfigService configService, ObjectMapper objectMapper) {
        this.sqs = sqs;
        this.queueUrl = configService.getEnvironmentVariable(SQS_AUDIT_EVENT_QUEUE_URL);
        this.objectMapper = objectMapper;
        this.configService = configService;
    }

    public static SqsClient getSqsClient() {
        return SqsClient.builder()
                .region(EU_WEST_2)
                .httpClientBuilder(UrlConnectionHttpClient.builder())
                .build();
    }

    public void sendAuditEvent(AuditEvent auditEvent) throws SqsException {
        try {
            if (!configService.enabled(CoreFeatureFlag.DEVICE_INFORMATION)
                    && auditEvent.getRestricted() instanceof AuditRestrictedDeviceInformation) {
                auditEvent =
                        new AuditEvent(
                                auditEvent.getEventName(),
                                auditEvent.getComponentId(),
                                auditEvent.getUser(),
                                auditEvent.getExtensions());
            }
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
