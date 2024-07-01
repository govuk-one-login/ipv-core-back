package uk.gov.di.ipv.core.library.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.awssdk.http.crt.AwsCrtAsyncHttpClient;
import software.amazon.awssdk.services.sqs.SqsAsyncClient;
import software.amazon.awssdk.services.sqs.model.SendMessageRequest;
import software.amazon.awssdk.services.sqs.model.SendMessageResponse;
import uk.gov.di.ipv.core.library.auditing.AuditEvent;
import uk.gov.di.ipv.core.library.exceptions.SqsException;
import uk.gov.di.ipv.core.library.helpers.LogHelper;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;

import static software.amazon.awssdk.regions.Region.EU_WEST_2;
import static uk.gov.di.ipv.core.library.config.EnvironmentVariable.SQS_AUDIT_EVENT_QUEUE_URL;

public class AuditService {
    private static final Logger LOGGER = LogManager.getLogger();

    private final SqsAsyncClient sqs;
    private final String queueUrl;
    private final ObjectMapper objectMapper;

    private List<CompletableFuture<SendMessageResponse>> events = new ArrayList<>();

    public AuditService(SqsAsyncClient sqs, ConfigService configService) {
        this.sqs = sqs;
        this.queueUrl = configService.getEnvironmentVariable(SQS_AUDIT_EVENT_QUEUE_URL);
        this.objectMapper = new ObjectMapper();
    }

    public AuditService(
            SqsAsyncClient sqs, ConfigService configService, ObjectMapper objectMapper) {
        this.sqs = sqs;
        this.queueUrl = configService.getEnvironmentVariable(SQS_AUDIT_EVENT_QUEUE_URL);
        this.objectMapper = objectMapper;
    }

    public static SqsAsyncClient getSqsClient() {
        return SqsAsyncClient.builder()
                .region(EU_WEST_2)
                .httpClientBuilder(AwsCrtAsyncHttpClient.builder())
                .build();
    }

    public void sendAuditEvent(AuditEvent auditEvent) throws SqsException {
        try {
            var event =
                    sqs.sendMessage(
                            SendMessageRequest.builder()
                                    .queueUrl(queueUrl)
                                    .messageBody(objectMapper.writeValueAsString(auditEvent))
                                    .build());
            events.add(event);
        } catch (JsonProcessingException e) {
            throw new SqsException(e);
        }
    }

    // Await audit events MUST be called before the end of each handler
    public void awaitAuditEvents() {
        try {
            var eventsToAwait = events;
            events = new ArrayList<>();
            CompletableFuture.allOf(eventsToAwait.toArray(new CompletableFuture[0])).get();
        } catch (InterruptedException | ExecutionException e) {
            LOGGER.error(LogHelper.buildErrorMessage("Failed to send audit event(s)", e));
            throw new AuditException("Failed to send audit event(s)", e);
        }
    }
}
