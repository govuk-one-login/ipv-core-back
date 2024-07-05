package uk.gov.di.ipv.core.library.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.awssdk.http.urlconnection.UrlConnectionHttpClient;
import software.amazon.awssdk.services.sqs.SqsAsyncClient;
import software.amazon.awssdk.services.sqs.SqsClient;
import software.amazon.awssdk.services.sqs.model.SendMessageRequest;
import software.amazon.awssdk.services.sqs.model.SendMessageResponse;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.auditing.AuditEvent;
import uk.gov.di.ipv.core.library.exception.AuditException;
import uk.gov.di.ipv.core.library.exceptions.SqsException;
import uk.gov.di.ipv.core.library.helpers.LogHelper;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;

import static software.amazon.awssdk.regions.Region.EU_WEST_2;
import static uk.gov.di.ipv.core.library.config.CoreFeatureFlag.SQS_ASYNC;
import static uk.gov.di.ipv.core.library.config.EnvironmentVariable.SQS_AUDIT_EVENT_QUEUE_URL;

public class AuditService {
    private static final Logger LOGGER = LogManager.getLogger();
    private final SqsClients sqsClients;
    private final ObjectMapper objectMapper;
    private final ConfigService configService;
    private List<CompletableFuture<SendMessageResponse>> events = new ArrayList<>();

    public AuditService(SqsClients sqsClients, ConfigService configService) {
        this.sqsClients = sqsClients;
        this.configService = configService;
        this.objectMapper = new ObjectMapper();
    }

    public AuditService(
            SqsClients sqsClients, ConfigService configService, ObjectMapper objectMapper) {
        this.sqsClients = sqsClients;
        this.configService = configService;
        this.objectMapper = objectMapper;
    }

    // Credentials Provider should be set explicitly when creating a new "AwsClient" - not for
    // SnapStart...
    @SuppressWarnings("java:S6242")
    @ExcludeFromGeneratedCoverageReport
    public static SqsClients getSqsClients() {
        return new SqsClients(
                SqsClient.builder()
                        .region(EU_WEST_2)
                        .httpClientBuilder(UrlConnectionHttpClient.builder())
                        .build(),
                SqsAsyncClient.builder().region(EU_WEST_2).build());
    }

    public void sendAuditEvent(AuditEvent auditEvent) throws SqsException {
        var sendMessageRequest = buildSendMessageRequest(auditEvent);

        if (configService.enabled(SQS_ASYNC)) {
            events.add(sqsClients.sqsAsyncClient().sendMessage(sendMessageRequest));
        } else {
            sqsClients.sqsClient().sendMessage(sendMessageRequest);
        }
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

    private SendMessageRequest buildSendMessageRequest(AuditEvent auditEvent) throws SqsException {
        try {
            return SendMessageRequest.builder()
                    .queueUrl(configService.getEnvironmentVariable(SQS_AUDIT_EVENT_QUEUE_URL))
                    .messageBody(objectMapper.writeValueAsString(auditEvent))
                    .build();
        } catch (JsonProcessingException e) {
            throw new SqsException(e);
        }
    }
}
