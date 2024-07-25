package uk.gov.di.ipv.core.library.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.awssdk.services.sqs.SqsAsyncClient;
import software.amazon.awssdk.services.sqs.model.SendMessageRequest;
import software.amazon.awssdk.services.sqs.model.SendMessageResponse;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.auditing.AuditEvent;
import uk.gov.di.ipv.core.library.exception.AuditException;
import uk.gov.di.ipv.core.library.helpers.LogHelper;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;

import static software.amazon.awssdk.regions.Region.EU_WEST_2;
import static uk.gov.di.ipv.core.library.config.EnvironmentVariable.SQS_AUDIT_EVENT_QUEUE_URL;

public class SqsAuditService implements AuditService {
    private static final Logger LOGGER = LogManager.getLogger();
    private final SqsAsyncClient sqsClient;
    private final ObjectMapper objectMapper;
    private final ConfigService configService;
    private List<CompletableFuture<SendMessageResponse>> events = new ArrayList<>();

    public SqsAuditService(SqsAsyncClient sqsClient, ConfigService configService) {
        this.sqsClient = sqsClient;
        this.configService = configService;
        this.objectMapper = new ObjectMapper();
    }

    public SqsAuditService(
            SqsAsyncClient sqsClient, ConfigService configService, ObjectMapper objectMapper) {
        this.sqsClient = sqsClient;
        this.configService = configService;
        this.objectMapper = objectMapper;
    }

    // Credentials Provider should be set explicitly when creating a new "AwsClient" - not for
    // SnapStart...
    @SuppressWarnings("java:S6242")
    @ExcludeFromGeneratedCoverageReport
    public static SqsAsyncClient getSqsClient() {
        return SqsAsyncClient.builder().region(EU_WEST_2).build();
    }

    public void sendAuditEvent(AuditEvent auditEvent) {
        var sendMessageRequest = buildSendMessageRequest(auditEvent);
        events.add(sqsClient.sendMessage(sendMessageRequest));
    }

    public void awaitAuditEvents() {
        if (events.isEmpty()) {
            return;
        }

        try {
            var eventsToWait = events;
            events = new ArrayList<>();
            CompletableFuture.allOf(eventsToWait.toArray(new CompletableFuture[0])).get();
        } catch (InterruptedException | ExecutionException e) {
            if (e instanceof InterruptedException) {
                Thread.currentThread().interrupt();
            }
            LOGGER.error(LogHelper.buildErrorMessage("Failed to send audit event(s)", e));
            throw new AuditException("Failed to send audit event(s)", e);
        }
    }

    private SendMessageRequest buildSendMessageRequest(AuditEvent auditEvent) {
        try {
            return SendMessageRequest.builder()
                    .queueUrl(configService.getEnvironmentVariable(SQS_AUDIT_EVENT_QUEUE_URL))
                    .messageBody(objectMapper.writeValueAsString(auditEvent))
                    .build();
        } catch (JsonProcessingException e) {
            throw new AuditException("Could not serialise audit event", e);
        }
    }
}
