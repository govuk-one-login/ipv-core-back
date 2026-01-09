package uk.gov.di.ipv.core.library.service;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import software.amazon.awssdk.services.sqs.SqsAsyncClient;
import software.amazon.awssdk.services.sqs.model.SendMessageRequest;
import software.amazon.awssdk.services.sqs.model.SendMessageResponse;
import uk.gov.di.ipv.core.library.auditing.AuditEvent;
import uk.gov.di.ipv.core.library.auditing.AuditEventTypes;
import uk.gov.di.ipv.core.library.auditing.AuditEventUser;
import uk.gov.di.ipv.core.library.auditing.extension.AuditExtensionErrorParams;
import uk.gov.di.ipv.core.library.auditing.extension.AuditExtensionsUserIdentity;
import uk.gov.di.ipv.core.library.auditing.restricted.AuditRestrictedAsync;
import uk.gov.di.ipv.core.library.auditing.restricted.AuditRestrictedDeviceInformation;
import uk.gov.di.ipv.core.library.domain.AuditEventReturnCode;
import uk.gov.di.ipv.core.library.enums.Vot;
import uk.gov.di.ipv.core.library.exception.AuditException;
import uk.gov.di.ipv.core.library.helpers.vocab.NameGenerator;
import uk.gov.di.model.NamePart;

import java.util.List;
import java.util.concurrent.CompletableFuture;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.CALLS_REAL_METHODS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.mockito.quality.Strictness.LENIENT;
import static uk.gov.di.ipv.core.library.config.EnvironmentVariable.SQS_AUDIT_EVENT_QUEUE_URL;

@ExtendWith(MockitoExtension.class)
class SqsAuditServiceTest {
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final String RETURN_CODE_KEY = "returnCodes";
    private static final String FAILURE_RETURN_CODES_TEST =
            "[{\"code\":\"A\",\"issuers\":[\"https://review-d.account.gov.uk\",\"https://review-f.account.gov.uk\"]},{\"code\":\"V\",\"issuers\":[\"https://review-k.account.gov.uk\"]}]";

    @Mock private SqsAsyncClient mockSqsAsyncClient;
    @Mock private ConfigService mockConfigService;

    private AuditService auditService;

    @BeforeEach
    void setup() {
        when(mockConfigService.getEnvironmentVariable(SQS_AUDIT_EVENT_QUEUE_URL))
                .thenReturn("https://example-queue-url");

        auditService = new SqsAuditService(mockSqsAsyncClient, mockConfigService);
    }

    @Test
    void shouldSendMessageToSqsQueue() throws JsonProcessingException {
        // Arrange
        var event =
                AuditEvent.createWithoutDeviceInformation(
                        AuditEventTypes.IPV_JOURNEY_START, null, null, null, null);

        // Act
        auditService.sendAuditEvent(event);

        // Assert
        ArgumentCaptor<SendMessageRequest> sqsSendMessageRequestCaptor =
                ArgumentCaptor.forClass(SendMessageRequest.class);

        verify(mockSqsAsyncClient).sendMessage(sqsSendMessageRequestCaptor.capture());

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

        var event =
                AuditEvent.createWithoutDeviceInformation(
                        AuditEventTypes.IPV_JOURNEY_START, null, null, extensions);

        // Act
        auditService.sendAuditEvent(event);

        // Assert
        ArgumentCaptor<SendMessageRequest> sqsSendMessageRequestCaptor =
                ArgumentCaptor.forClass(SendMessageRequest.class);

        verify(mockSqsAsyncClient).sendMessage(sqsSendMessageRequestCaptor.capture());

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
                AuditEvent.createWithoutDeviceInformation(
                        AuditEventTypes.IPV_JOURNEY_START, null, auditEventUser, extensions);

        // Act
        auditService.sendAuditEvent(event);

        // Assert
        ArgumentCaptor<SendMessageRequest> sqsSendMessageRequestCaptor =
                ArgumentCaptor.forClass(SendMessageRequest.class);

        verify(mockSqsAsyncClient).sendMessage(sqsSendMessageRequestCaptor.capture());

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
            throws Exception {
        // Arrange
        AuditExtensionsUserIdentity extensions =
                new AuditExtensionsUserIdentity(Vot.P2, false, false, null);
        var event =
                AuditEvent.createWithoutDeviceInformation(
                        AuditEventTypes.IPV_JOURNEY_START, null, null, extensions);

        // Act
        auditService.sendAuditEvent(event);

        ArgumentCaptor<SendMessageRequest> sqsSendMessageRequestCaptor =
                ArgumentCaptor.forClass(SendMessageRequest.class);

        verify(mockSqsAsyncClient).sendMessage(sqsSendMessageRequestCaptor.capture());

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
            throws Exception {
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
        var event =
                AuditEvent.createWithoutDeviceInformation(
                        AuditEventTypes.IPV_JOURNEY_START, null, null, extensions);

        // Act
        auditService.sendAuditEvent(event);

        // Assert
        ArgumentCaptor<SendMessageRequest> sqsSendMessageRequestCaptor =
                ArgumentCaptor.forClass(SendMessageRequest.class);

        verify(mockSqsAsyncClient).sendMessage(sqsSendMessageRequestCaptor.capture());

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
    void shouldSendMessageToSqsQueueWithRestrictedDeviceInfo() throws Exception {
        // Arrange
        var event =
                AuditEvent.createWithDeviceInformation(
                        AuditEventTypes.IPV_JOURNEY_START,
                        null,
                        null,
                        null,
                        new AuditRestrictedDeviceInformation("TEST_DEVICE"));

        // Act
        auditService.sendAuditEvent(event);

        // Assert
        ArgumentCaptor<SendMessageRequest> sqsSendMessageRequestCaptor =
                ArgumentCaptor.forClass(SendMessageRequest.class);

        verify(mockSqsAsyncClient).sendMessage(sqsSendMessageRequestCaptor.capture());

        assertEquals(
                "https://example-queue-url", sqsSendMessageRequestCaptor.getValue().queueUrl());

        String json = sqsSendMessageRequestCaptor.getValue().messageBody();
        ObjectMapper mapper = new ObjectMapper();
        JsonParser parser = mapper.createParser(json);
        JsonNode node = mapper.readTree(parser);

        assertTrue(node.has("restricted"));
        assertTrue(node.get("restricted").has("device_information"));
    }

    @Test
    void shouldSendMessageToSqsQueueWithRestrictedF2F() throws Exception {
        // Arrange
        List<uk.gov.di.model.Name> name =
                List.of(
                        NameGenerator.createName(
                                List.of(
                                        NameGenerator.NamePartGenerator.createNamePart(
                                                "first_name", NamePart.NamePartType.GIVEN_NAME))));
        var event =
                AuditEvent.createWithoutDeviceInformation(
                        AuditEventTypes.IPV_JOURNEY_START,
                        null,
                        null,
                        null,
                        new AuditRestrictedAsync(name));

        // Act
        auditService.sendAuditEvent(event);

        // Assert
        ArgumentCaptor<SendMessageRequest> sqsSendMessageRequestCaptor =
                ArgumentCaptor.forClass(SendMessageRequest.class);

        verify(mockSqsAsyncClient).sendMessage(sqsSendMessageRequestCaptor.capture());

        assertEquals(
                "https://example-queue-url", sqsSendMessageRequestCaptor.getValue().queueUrl());

        String json = sqsSendMessageRequestCaptor.getValue().messageBody();
        ObjectMapper mapper = new ObjectMapper();
        JsonParser parser = mapper.createParser(json);
        JsonNode node = mapper.readTree(parser);

        assertTrue(node.has("restricted"));
        assertTrue(node.get("restricted").has("name"));
    }

    @Test
    void shouldThrowAuditException() throws Exception {
        var mockObjectMapper = mock(ObjectMapper.class);
        var underTest =
                new SqsAuditService(mockSqsAsyncClient, mockConfigService, mockObjectMapper);
        var event =
                AuditEvent.createWithoutDeviceInformation(
                        AuditEventTypes.IPV_JOURNEY_START,
                        "{\\}",
                        new AuditEventUser("1234", "1234", "1234", "1.1.1.1"));
        when(mockObjectMapper.writeValueAsString(any(AuditEvent.class)))
                .thenThrow(new JsonProcessingException("") {});

        assertThrows(AuditException.class, () -> underTest.sendAuditEvent(event));
    }

    @Test
    void awaitAuditEventsShouldWaitForAllAuditEventsToComplete() throws Exception {
        var completableFutureOne = new CompletableFuture<SendMessageResponse>();
        var completableFutureTwo = new CompletableFuture<SendMessageResponse>();
        var completableFutureThree = new CompletableFuture<SendMessageResponse>();

        when(mockSqsAsyncClient.sendMessage(any(SendMessageRequest.class)))
                .thenReturn(completableFutureOne)
                .thenReturn(completableFutureTwo)
                .thenReturn(completableFutureThree);

        var event = mock(AuditEvent.class);
        auditService.sendAuditEvent(event);
        auditService.sendAuditEvent(event);
        auditService.sendAuditEvent(event);

        var mockAllOfCompletableFuture = mock(CompletableFuture.class);

        try (var completableFutureMockedStatic = mockStatic(CompletableFuture.class)) {
            completableFutureMockedStatic
                    .when(() -> CompletableFuture.allOf(any(CompletableFuture[].class)))
                    .thenAnswer(
                            invocation -> {
                                assertEquals(3, invocation.getArguments().length);

                                assertEquals(completableFutureOne, invocation.getArgument(0));
                                assertEquals(completableFutureTwo, invocation.getArgument(1));
                                assertEquals(completableFutureThree, invocation.getArgument(2));

                                return mockAllOfCompletableFuture;
                            });

            auditService.awaitAuditEvents();
        }

        verify(mockAllOfCompletableFuture).get();
    }

    @Test
    void awaitAuditEventsShouldThrowAuditExceptionIfFuturesCompleteExceptionally() {
        var exceptionCompletableFuture = new CompletableFuture<SendMessageResponse>();
        exceptionCompletableFuture.completeExceptionally(
                new IllegalArgumentException("A bad thing happens in the future"));

        when(mockSqsAsyncClient.sendMessage(any(SendMessageRequest.class)))
                .thenReturn(exceptionCompletableFuture);

        var event = mock(AuditEvent.class);
        auditService.sendAuditEvent(event);

        var auditException =
                assertThrows(AuditException.class, () -> auditService.awaitAuditEvents());
        assertEquals("Failed to send audit event(s)", auditException.getMessage());
    }

    @Test
    @MockitoSettings(strictness = LENIENT)
    void awaitAuditEventsShouldThrowAuditExceptionIfThreadInterruptedWhileWaiting()
            throws Exception {
        var mockAllOfCompletableFuture = mock(CompletableFuture.class);
        when(mockAllOfCompletableFuture.get()).thenThrow(new InterruptedException("Excuse me..."));

        try (var completableFutureMockedStatic =
                mockStatic(CompletableFuture.class, CALLS_REAL_METHODS)) {
            completableFutureMockedStatic
                    .when(() -> CompletableFuture.allOf(any(CompletableFuture[].class)))
                    .thenReturn(mockAllOfCompletableFuture);

            var event =
                    AuditEvent.createWithoutDeviceInformation(
                            AuditEventTypes.IPV_JOURNEY_START, null, null, null, null);
            auditService.sendAuditEvent(event);

            var auditException =
                    assertThrows(AuditException.class, () -> auditService.awaitAuditEvents());

            assertEquals("Failed to send audit event(s)", auditException.getMessage());
            assertTrue(Thread.interrupted());
        }
    }
}
