package uk.gov.di.ipv.core.library.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import software.amazon.awssdk.services.sqs.SqsClient;
import software.amazon.awssdk.services.sqs.model.SendMessageRequest;
import uk.gov.di.ipv.core.library.auditing.AuditEvent;
import uk.gov.di.ipv.core.library.auditing.AuditEventTypes;
import uk.gov.di.ipv.core.library.auditing.AuditEventUser;
import uk.gov.di.ipv.core.library.auditing.extension.AuditExtensionErrorParams;
import uk.gov.di.ipv.core.library.auditing.extension.AuditExtensionsUserIdentity;
import uk.gov.di.ipv.core.library.domain.AuditEventReturnCode;
import uk.gov.di.ipv.core.library.enums.Vot;
import uk.gov.di.ipv.core.library.exceptions.SqsException;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.config.EnvironmentVariable.SQS_AUDIT_EVENT_QUEUE_URL;

@ExtendWith(MockitoExtension.class)
class AuditServiceTest {
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final String RETURN_CODE_KEY = "returnCodes";
    private static final String FAILURE_RETURN_CODES_TEST =
            "[{\"code\":\"A\",\"issuers\":[\"https://review-d.account.gov.uk\",\"https://review-f.account.gov.uk\"]},{\"code\":\"V\",\"issuers\":[\"https://review-k.account.gov.uk\"]}]";

    private AuditService auditService;

    @Mock private SqsClient mockSqs;
    @Mock private ConfigService mockConfigService;

    @BeforeEach
    void setup() {
        when(mockConfigService.getEnvironmentVariable(SQS_AUDIT_EVENT_QUEUE_URL))
                .thenReturn("https://example-queue-url");

        auditService = new AuditService(mockSqs, mockConfigService);
    }

    @Test
    void shouldSendMessageToSqsQueue() throws JsonProcessingException, SqsException {

        // Arrange
        var event = new AuditEvent(AuditEventTypes.IPV_JOURNEY_START, null, null, null);

        // Act
        auditService.sendAuditEvent(event);

        // Assert
        ArgumentCaptor<SendMessageRequest> sqsSendMessageRequestCaptor =
                ArgumentCaptor.forClass(SendMessageRequest.class);
        verify(mockSqs).sendMessage(sqsSendMessageRequestCaptor.capture());

        assertEquals(
                "https://example-queue-url", sqsSendMessageRequestCaptor.getValue().queueUrl());

        AuditEvent messageBody =
                OBJECT_MAPPER.readValue(
                        sqsSendMessageRequestCaptor.getValue().messageBody(), AuditEvent.class);
        assertEquals(AuditEventTypes.IPV_JOURNEY_START, messageBody.getEventName());
    }

    @Test
    void shouldSendMessageToSqsQueueWithAuditExtensionErrorParams() throws Exception {

        // Arrange
        String errorCode = "server_error";
        String errorDescription = "Test error";
        AuditExtensionErrorParams extensions =
                new AuditExtensionErrorParams.Builder()
                        .setErrorCode(errorCode)
                        .setErrorDescription(errorDescription)
                        .build();

        var event = new AuditEvent(AuditEventTypes.IPV_JOURNEY_START, null, null, extensions);

        // Act
        auditService.sendAuditEvent(event);

        // Assert
        ArgumentCaptor<SendMessageRequest> sqsSendMessageRequestCaptor =
                ArgumentCaptor.forClass(SendMessageRequest.class);
        verify(mockSqs).sendMessage(sqsSendMessageRequestCaptor.capture());

        assertEquals(
                "https://example-queue-url", sqsSendMessageRequestCaptor.getValue().queueUrl());

        JsonNode messageBody =
                OBJECT_MAPPER.readTree(sqsSendMessageRequestCaptor.getValue().messageBody());
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

        // Arrange
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

        var event =
                new AuditEvent(AuditEventTypes.IPV_JOURNEY_START, null, auditEventUser, extensions);

        // Act
        auditService.sendAuditEvent(event);

        // Assert
        ArgumentCaptor<SendMessageRequest> sqsSendMessageRequestCaptor =
                ArgumentCaptor.forClass(SendMessageRequest.class);
        verify(mockSqs).sendMessage(sqsSendMessageRequestCaptor.capture());

        assertEquals(
                "https://example-queue-url", sqsSendMessageRequestCaptor.getValue().queueUrl());

        JsonNode messageBody =
                OBJECT_MAPPER.readTree(sqsSendMessageRequestCaptor.getValue().messageBody());
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

        // Arrange
        AuditExtensionsUserIdentity extensions =
                new AuditExtensionsUserIdentity(Vot.P2, false, false, null);
        var event = new AuditEvent(AuditEventTypes.IPV_JOURNEY_START, null, null, extensions);

        // Act
        auditService.sendAuditEvent(event);

        ArgumentCaptor<SendMessageRequest> sqsSendMessageRequestCaptor =
                ArgumentCaptor.forClass(SendMessageRequest.class);
        verify(mockSqs).sendMessage(sqsSendMessageRequestCaptor.capture());

        assertEquals(
                "https://example-queue-url", sqsSendMessageRequestCaptor.getValue().queueUrl());

        JsonNode messageBody =
                OBJECT_MAPPER.readTree(sqsSendMessageRequestCaptor.getValue().messageBody());
        assertEquals(
                AuditEventTypes.IPV_JOURNEY_START.toString(),
                messageBody.get("event_name").asText());
        JsonNode auditExtensionsUserIdentity = messageBody.get("extensions");
        assertNull(auditExtensionsUserIdentity.get(RETURN_CODE_KEY));
    }

    @Test
    void shouldSendMessageToSqsQueueWithAuditExtensionsUserIdentityWithFailureCodes()
            throws JsonProcessingException, SqsException {

        // Arrange
        List<AuditEventReturnCode> auditEventReturnCodes =
                List.of(
                        new AuditEventReturnCode(
                                "A",
                                List.of(
                                        "https://review-d.account.gov.uk",
                                        "https://review-f.account.gov.uk")),
                        new AuditEventReturnCode("V", List.of("https://review-k.account.gov.uk")));
        AuditExtensionsUserIdentity extensions =
                new AuditExtensionsUserIdentity(Vot.P2, false, false, auditEventReturnCodes);
        var event = new AuditEvent(AuditEventTypes.IPV_JOURNEY_START, null, null, extensions);

        // Act
        auditService.sendAuditEvent(event);

        // Assert
        ArgumentCaptor<SendMessageRequest> sqsSendMessageRequestCaptor =
                ArgumentCaptor.forClass(SendMessageRequest.class);
        verify(mockSqs).sendMessage(sqsSendMessageRequestCaptor.capture());

        assertEquals(
                "https://example-queue-url", sqsSendMessageRequestCaptor.getValue().queueUrl());

        JsonNode messageBody =
                OBJECT_MAPPER.readTree(sqsSendMessageRequestCaptor.getValue().messageBody());
        assertEquals(
                AuditEventTypes.IPV_JOURNEY_START.toString(),
                messageBody.get("event_name").asText());
        JsonNode auditExtensionsUserIdentity = messageBody.get("extensions");
        JsonNode returnCodeJson = auditExtensionsUserIdentity.get(RETURN_CODE_KEY);
        assertEquals(2, returnCodeJson.size());
        assertEquals(OBJECT_MAPPER.readTree(FAILURE_RETURN_CODES_TEST), returnCodeJson);
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
