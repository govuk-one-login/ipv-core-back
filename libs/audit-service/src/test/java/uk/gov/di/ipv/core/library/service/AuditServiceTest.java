package uk.gov.di.ipv.core.library.service;

import com.amazonaws.services.sqs.AmazonSQS;
import com.amazonaws.services.sqs.model.SendMessageRequest;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.auditing.AuditEvent;
import uk.gov.di.ipv.core.library.auditing.AuditEventTypes;
import uk.gov.di.ipv.core.library.auditing.AuditEventUser;
import uk.gov.di.ipv.core.library.auditing.extension.AuditExtensionErrorParams;
import uk.gov.di.ipv.core.library.auditing.extension.AuditExtensionsUserIdentity;
import uk.gov.di.ipv.core.library.exceptions.SqsException;

import java.util.ArrayList;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.config.EnvironmentVariable.SQS_AUDIT_EVENT_QUEUE_URL;

@ExtendWith(MockitoExtension.class)
class AuditServiceTest {

    @Mock AmazonSQS mockSqs;
    @Mock ConfigService mockConfigService;

    private final ObjectMapper objectMapper = new ObjectMapper();

    private AuditService auditService;

    @BeforeEach
    void setup() {
        when(mockConfigService.getEnvironmentVariable(SQS_AUDIT_EVENT_QUEUE_URL))
                .thenReturn("https://example-queue-url");

        auditService = new AuditService(mockSqs, mockConfigService);
    }

    @Test
    void shouldSendMessageToSqsQueue() throws JsonProcessingException, SqsException {
        auditService.sendAuditEvent(AuditEventTypes.IPV_JOURNEY_START);

        ArgumentCaptor<SendMessageRequest> sqsSendMessageRequestCaptor =
                ArgumentCaptor.forClass(SendMessageRequest.class);
        verify(mockSqs).sendMessage(sqsSendMessageRequestCaptor.capture());

        assertEquals(
                "https://example-queue-url", sqsSendMessageRequestCaptor.getValue().getQueueUrl());

        AuditEvent messageBody =
                objectMapper.readValue(
                        sqsSendMessageRequestCaptor.getValue().getMessageBody(), AuditEvent.class);
        assertEquals(AuditEventTypes.IPV_JOURNEY_START, messageBody.getEventName());
    }

    @Test
    void shouldSendMessageToSqsQueueWithAuditExtensionErrorParams()
            throws JsonProcessingException, SqsException {
        String errorCode = "server_error";
        String errorDescription = "Test error";
        AuditExtensionErrorParams extensions =
                new AuditExtensionErrorParams.Builder()
                        .setErrorCode(errorCode)
                        .setErrorDescription(errorDescription)
                        .build();
        auditService.sendAuditEvent(AuditEventTypes.IPV_JOURNEY_START, extensions);

        ArgumentCaptor<SendMessageRequest> sqsSendMessageRequestCaptor =
                ArgumentCaptor.forClass(SendMessageRequest.class);
        verify(mockSqs).sendMessage(sqsSendMessageRequestCaptor.capture());

        assertEquals(
                "https://example-queue-url", sqsSendMessageRequestCaptor.getValue().getQueueUrl());

        JsonNode messageBody =
                objectMapper.readTree(sqsSendMessageRequestCaptor.getValue().getMessageBody());
        assertEquals(
                AuditEventTypes.IPV_JOURNEY_START.toString(),
                messageBody.get("event_name").asText());
        JsonNode auditExtensionErrorParams = messageBody.get("extensions");
        assertEquals(
                extensions.getErrorCode(), auditExtensionErrorParams.get("error_code").asText());
        assertEquals(
                extensions.getErrorDescription(),
                auditExtensionErrorParams.get("error_description").asText());
    }

    @Test
    void shouldSendMessageToQueueWithExtensionsAndUser() throws Exception {
        String errorCode = "server_error";
        String errorDescription = "Test error";
        AuditExtensionErrorParams extensions =
                new AuditExtensionErrorParams.Builder()
                        .setErrorCode(errorCode)
                        .setErrorDescription(errorDescription)
                        .build();

        AuditEventUser auditEventUser =
                new AuditEventUser(
                        "someUserId",
                        "someSessionId",
                        "someGovukSigninJourneyId",
                        "someIp.Address");

        auditService.sendAuditEvent(AuditEventTypes.IPV_JOURNEY_START, extensions, auditEventUser);

        ArgumentCaptor<SendMessageRequest> sqsSendMessageRequestCaptor =
                ArgumentCaptor.forClass(SendMessageRequest.class);
        verify(mockSqs).sendMessage(sqsSendMessageRequestCaptor.capture());

        assertEquals(
                "https://example-queue-url", sqsSendMessageRequestCaptor.getValue().getQueueUrl());

        JsonNode messageBody =
                objectMapper.readTree(sqsSendMessageRequestCaptor.getValue().getMessageBody());
        assertEquals(
                AuditEventTypes.IPV_JOURNEY_START.toString(),
                messageBody.get("event_name").asText());
        JsonNode auditExtensionErrorParams = messageBody.get("extensions");
        assertEquals(
                extensions.getErrorCode(), auditExtensionErrorParams.get("error_code").asText());
        assertEquals(
                extensions.getErrorDescription(),
                auditExtensionErrorParams.get("error_description").asText());
        assertEquals("someUserId", messageBody.get("user").get("user_id").asText());
        assertEquals("someSessionId", messageBody.get("user").get("session_id").asText());
        assertEquals(
                "someGovukSigninJourneyId",
                messageBody.get("user").get("govuk_signin_journey_id").asText());
    }

    @Test
    void shouldSendMessageToSqsQueueWithAuditExtensionsUserIdentityWithoutExitCode()
            throws JsonProcessingException, SqsException {
        AuditExtensionsUserIdentity extensions =
                new AuditExtensionsUserIdentity("levelOFConfidence", false, false, null);
        auditService.sendAuditEvent(AuditEventTypes.IPV_JOURNEY_START, extensions);

        ArgumentCaptor<SendMessageRequest> sqsSendMessageRequestCaptor =
                ArgumentCaptor.forClass(SendMessageRequest.class);
        verify(mockSqs).sendMessage(sqsSendMessageRequestCaptor.capture());

        assertEquals(
                "https://example-queue-url", sqsSendMessageRequestCaptor.getValue().getQueueUrl());

        JsonNode messageBody =
                objectMapper.readTree(sqsSendMessageRequestCaptor.getValue().getMessageBody());
        assertEquals(
                AuditEventTypes.IPV_JOURNEY_START.toString(),
                messageBody.get("event_name").asText());
        JsonNode auditExtensionsUserIdentity = messageBody.get("extensions");
        assertNull(auditExtensionsUserIdentity.get("exit_code"));
    }

    @Test
    void shouldSendMessageToSqsQueueWithAuditExtensionsUserIdentityWithExitCode()
            throws JsonProcessingException, SqsException {
        AuditExtensionsUserIdentity extensions =
                new AuditExtensionsUserIdentity(
                        "levelOFConfidence", false, false, new ArrayList<>());
        auditService.sendAuditEvent(AuditEventTypes.IPV_JOURNEY_START, extensions);

        ArgumentCaptor<SendMessageRequest> sqsSendMessageRequestCaptor =
                ArgumentCaptor.forClass(SendMessageRequest.class);
        verify(mockSqs).sendMessage(sqsSendMessageRequestCaptor.capture());

        assertEquals(
                "https://example-queue-url", sqsSendMessageRequestCaptor.getValue().getQueueUrl());

        JsonNode messageBody =
                objectMapper.readTree(sqsSendMessageRequestCaptor.getValue().getMessageBody());
        assertEquals(
                AuditEventTypes.IPV_JOURNEY_START.toString(),
                messageBody.get("event_name").asText());
        JsonNode auditExtensionsUserIdentity = messageBody.get("extensions");
        assertNotNull(auditExtensionsUserIdentity.get("exit_code"));
    }

    @Test
    void shouldThrowSQSException() throws JsonProcessingException {
        ObjectMapper mockObjectMapper = mock(ObjectMapper.class);
        AuditService underTest = new AuditService(mockSqs, mockConfigService, mockObjectMapper);
        when(mockObjectMapper.writeValueAsString(any(AuditEvent.class)))
                .thenThrow(new JsonProcessingException("") {});
        assertThrows(
                SqsException.class,
                () ->
                        underTest.sendAuditEvent(
                                new AuditEvent(
                                        AuditEventTypes.IPV_JOURNEY_START,
                                        "{\\}",
                                        new AuditEventUser("1234", "1234", "1234", "1.1.1.1"))));
    }
}
