package uk.gov.di.ipv.core.library.service;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import software.amazon.awssdk.services.sqs.SqsAsyncClient;
import software.amazon.awssdk.services.sqs.SqsClient;
import software.amazon.awssdk.services.sqs.model.SendMessageRequest;
import software.amazon.awssdk.services.sqs.model.SendMessageResponse;
import uk.gov.di.ipv.core.library.auditing.AuditEvent;
import uk.gov.di.ipv.core.library.auditing.AuditEventTypes;
import uk.gov.di.ipv.core.library.auditing.AuditEventUser;
import uk.gov.di.ipv.core.library.auditing.extension.AuditExtensionErrorParams;
import uk.gov.di.ipv.core.library.auditing.extension.AuditExtensionsUserIdentity;
import uk.gov.di.ipv.core.library.auditing.restricted.AuditRestrictedDeviceInformation;
import uk.gov.di.ipv.core.library.auditing.restricted.AuditRestrictedF2F;
import uk.gov.di.ipv.core.library.domain.AuditEventReturnCode;
import uk.gov.di.ipv.core.library.domain.Name;
import uk.gov.di.ipv.core.library.domain.NameParts;
import uk.gov.di.ipv.core.library.enums.Vot;
import uk.gov.di.ipv.core.library.exception.AuditException;
import uk.gov.di.ipv.core.library.exceptions.SqsException;

import java.util.List;
import java.util.concurrent.CompletableFuture;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.mockito.quality.Strictness.LENIENT;
import static uk.gov.di.ipv.core.library.config.CoreFeatureFlag.SQS_ASYNC;
import static uk.gov.di.ipv.core.library.config.EnvironmentVariable.SQS_AUDIT_EVENT_QUEUE_URL;

@ExtendWith(MockitoExtension.class)
class AuditServiceTest {
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final String RETURN_CODE_KEY = "returnCodes";
    private static final String FAILURE_RETURN_CODES_TEST =
            "[{\"code\":\"A\",\"issuers\":[\"https://review-d.account.gov.uk\",\"https://review-f.account.gov.uk\"]},{\"code\":\"V\",\"issuers\":[\"https://review-k.account.gov.uk\"]}]";

    @Mock private SqsClient mockSqsClient;
    @Mock private SqsAsyncClient mockSqsAsyncClient;
    @Mock private ConfigService mockConfigService;

    private AuditService auditService;

    @BeforeEach
    void setup() {
        when(mockConfigService.getEnvironmentVariable(SQS_AUDIT_EVENT_QUEUE_URL))
                .thenReturn("https://example-queue-url");

        auditService =
                new AuditService(
                        new SqsClients(mockSqsClient, mockSqsAsyncClient), mockConfigService);
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void shouldSendMessageToSqsQueue(boolean sqsAsyncEnabled)
            throws JsonProcessingException, SqsException {
        // Arrange
        when(mockConfigService.enabled(SQS_ASYNC)).thenReturn(sqsAsyncEnabled);
        var event =
                AuditEvent.createWithoutDeviceInformation(
                        AuditEventTypes.IPV_JOURNEY_START, null, null, null, null);

        // Act
        auditService.sendAuditEvent(event);

        // Assert
        ArgumentCaptor<SendMessageRequest> sqsSendMessageRequestCaptor =
                ArgumentCaptor.forClass(SendMessageRequest.class);

        if (sqsAsyncEnabled) {
            verify(mockSqsAsyncClient).sendMessage(sqsSendMessageRequestCaptor.capture());
        } else {
            verify(mockSqsClient).sendMessage(sqsSendMessageRequestCaptor.capture());
        }

        assertEquals(
                "https://example-queue-url", sqsSendMessageRequestCaptor.getValue().queueUrl());

        AuditEvent messageBody =
                OBJECT_MAPPER.readValue(
                        sqsSendMessageRequestCaptor.getValue().messageBody(), AuditEvent.class);
        assertEquals(AuditEventTypes.IPV_JOURNEY_START, messageBody.getEventName());
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void shouldSendMessageToSqsQueueWithAuditExtensionErrorParams(boolean sqsAsyncEnabled)
            throws Exception {
        // Arrange
        when(mockConfigService.enabled(SQS_ASYNC)).thenReturn(sqsAsyncEnabled);
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

        if (sqsAsyncEnabled) {
            verify(mockSqsAsyncClient).sendMessage(sqsSendMessageRequestCaptor.capture());
        } else {
            verify(mockSqsClient).sendMessage(sqsSendMessageRequestCaptor.capture());
        }

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

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void shouldSendMessageToQueueWithExtensionsAndUser(boolean sqsAsyncEnabled) throws Exception {
        // Arrange
        when(mockConfigService.enabled(SQS_ASYNC)).thenReturn(sqsAsyncEnabled);
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

        if (sqsAsyncEnabled) {
            verify(mockSqsAsyncClient).sendMessage(sqsSendMessageRequestCaptor.capture());
        } else {
            verify(mockSqsClient).sendMessage(sqsSendMessageRequestCaptor.capture());
        }

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

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void shouldSendMessageToSqsQueueWithAuditExtensionsUserIdentityWithoutExitCode(
            boolean sqsAsyncEnabled) throws JsonProcessingException, SqsException {
        // Arrange
        when(mockConfigService.enabled(SQS_ASYNC)).thenReturn(sqsAsyncEnabled);
        AuditExtensionsUserIdentity extensions =
                new AuditExtensionsUserIdentity(Vot.P2, false, false, null);
        var event =
                AuditEvent.createWithoutDeviceInformation(
                        AuditEventTypes.IPV_JOURNEY_START, null, null, extensions);

        // Act
        auditService.sendAuditEvent(event);

        ArgumentCaptor<SendMessageRequest> sqsSendMessageRequestCaptor =
                ArgumentCaptor.forClass(SendMessageRequest.class);

        if (sqsAsyncEnabled) {
            verify(mockSqsAsyncClient).sendMessage(sqsSendMessageRequestCaptor.capture());
        } else {
            verify(mockSqsClient).sendMessage(sqsSendMessageRequestCaptor.capture());
        }

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

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void shouldSendMessageToSqsQueueWithAuditExtensionsUserIdentityWithFailureCodes(
            boolean sqsAsyncEnabled) throws JsonProcessingException, SqsException {
        // Arrange
        when(mockConfigService.enabled(SQS_ASYNC)).thenReturn(sqsAsyncEnabled);
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

        if (sqsAsyncEnabled) {
            verify(mockSqsAsyncClient).sendMessage(sqsSendMessageRequestCaptor.capture());
        } else {
            verify(mockSqsClient).sendMessage(sqsSendMessageRequestCaptor.capture());
        }

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

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void shouldSendMessageToSqsQueueWithRestrictedDeviceInfo(boolean sqsAsyncEnabled)
            throws Exception {
        // Arrange
        when(mockConfigService.enabled(SQS_ASYNC)).thenReturn(sqsAsyncEnabled);
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

        if (sqsAsyncEnabled) {
            verify(mockSqsAsyncClient).sendMessage(sqsSendMessageRequestCaptor.capture());
        } else {
            verify(mockSqsClient).sendMessage(sqsSendMessageRequestCaptor.capture());
        }

        assertEquals(
                "https://example-queue-url", sqsSendMessageRequestCaptor.getValue().queueUrl());

        String json = sqsSendMessageRequestCaptor.getValue().messageBody();
        ObjectMapper mapper = new ObjectMapper();
        JsonParser parser = mapper.createParser(json);
        JsonNode node = mapper.readTree(parser);

        assertTrue(node.has("restricted"));
        assertTrue(node.get("restricted").has("device_information"));
    }

    @ParameterizedTest
    @ValueSource(booleans = {true, false})
    void shouldSendMessageToSqsQueueWithRestrictedF2F(boolean sqsAsyncEnabled) throws Exception {
        // Arrange
        when(mockConfigService.enabled(SQS_ASYNC)).thenReturn(sqsAsyncEnabled);
        List<Name> name = List.of(new Name(List.of(new NameParts("first_name", "TestUser"))));
        var event =
                AuditEvent.createWithoutDeviceInformation(
                        AuditEventTypes.IPV_JOURNEY_START,
                        null,
                        null,
                        null,
                        new AuditRestrictedF2F(name));

        // Act
        auditService.sendAuditEvent(event);

        // Assert
        ArgumentCaptor<SendMessageRequest> sqsSendMessageRequestCaptor =
                ArgumentCaptor.forClass(SendMessageRequest.class);

        if (sqsAsyncEnabled) {
            verify(mockSqsAsyncClient).sendMessage(sqsSendMessageRequestCaptor.capture());
        } else {
            verify(mockSqsClient).sendMessage(sqsSendMessageRequestCaptor.capture());
        }

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
    void shouldThrowSQSException() throws JsonProcessingException {
        ObjectMapper mockObjectMapper = mock(ObjectMapper.class);
        AuditService underTest =
                new AuditService(
                        new SqsClients(mockSqsClient, mockSqsAsyncClient),
                        mockConfigService,
                        mockObjectMapper);
        when(mockObjectMapper.writeValueAsString(any(AuditEvent.class)))
                .thenThrow(new JsonProcessingException("") {});
        assertThrows(
                SqsException.class,
                () ->
                        underTest.sendAuditEvent(
                                AuditEvent.createWithoutDeviceInformation(
                                        AuditEventTypes.IPV_JOURNEY_START,
                                        "{\\}",
                                        new AuditEventUser("1234", "1234", "1234", "1.1.1.1"))));
    }

    @Test
    void awaitAuditEventsShouldWaitForAllAuditEventsToComplete() throws Exception {
        when(mockConfigService.enabled(SQS_ASYNC)).thenReturn(true);

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
    void awaitAuditEventsShouldThrowAuditExceptionIfFuturesCompleteExceptionally()
            throws Exception {
        when(mockConfigService.enabled(SQS_ASYNC)).thenReturn(true);
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
        when(mockConfigService.enabled(SQS_ASYNC)).thenReturn(true);

        var mockAllOfCompletableFuture = mock(CompletableFuture.class);
        when(mockAllOfCompletableFuture.get()).thenThrow(new InterruptedException("Excuse me..."));

        try (var completableFutureMockedStatic = mockStatic(CompletableFuture.class)) {
            completableFutureMockedStatic
                    .when(() -> CompletableFuture.allOf(any(CompletableFuture[].class)))
                    .thenReturn(mockAllOfCompletableFuture);

            var auditException =
                    assertThrows(AuditException.class, () -> auditService.awaitAuditEvents());

            assertEquals("Failed to send audit event(s)", auditException.getMessage());
            assertTrue(Thread.interrupted());
        }
    }

    @Test
    @MockitoSettings(strictness = LENIENT)
    void awaitAuditEventsShouldDoNothingIfNotUsingAsync() {
        when(mockConfigService.enabled(SQS_ASYNC)).thenReturn(false);

        try (var completableFutureMockedStatic = mockStatic(CompletableFuture.class)) {
            auditService.awaitAuditEvents();
            completableFutureMockedStatic.verifyNoInteractions();
        }
    }
}
