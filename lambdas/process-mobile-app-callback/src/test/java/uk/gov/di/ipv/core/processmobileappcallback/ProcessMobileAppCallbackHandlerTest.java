package uk.gov.di.ipv.core.processmobileappcallback;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import software.amazon.awssdk.http.HttpStatusCode;
import uk.gov.di.ipv.core.library.auditing.AuditEvent;
import uk.gov.di.ipv.core.library.auditing.AuditEventTypes;
import uk.gov.di.ipv.core.library.criresponse.service.CriResponseService;
import uk.gov.di.ipv.core.library.domain.Cri;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.JourneyErrorResponse;
import uk.gov.di.ipv.core.library.domain.JourneyResponse;
import uk.gov.di.ipv.core.library.exceptions.ClientOauthSessionNotFoundException;
import uk.gov.di.ipv.core.library.exceptions.IpvSessionNotFoundException;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.CriOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.CriResponseItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.ClientOAuthSessionDetailsService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.CriOAuthSessionService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.testhelpers.unit.LogCollector;
import uk.gov.di.ipv.core.processmobileappcallback.dto.MobileAppCallbackRequest;

import java.util.Map;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.StringContains.containsString;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_BUILD_CLIENT_OAUTH_RESPONSE_PATH;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_ERROR_PATH;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_NEXT_PATH;

@ExtendWith(MockitoExtension.class)
class ProcessMobileAppCallbackHandlerTest {
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final String TEST_IPV_SESSION_ID = "test_ipv_session_id";
    private static final String TEST_CLIENT_OAUTH_SESSION_ID = "test_client_oauth_id";
    private static final String TEST_OAUTH_STATE = "test_oauth_state";
    private static final String TEST_USER_ID = "test_user_id";
    @Mock private Context mockContext;
    @Mock private ConfigService configService;
    @Mock private IpvSessionService ipvSessionService;
    @Mock private CriOAuthSessionService criOAuthSessionService;
    @Mock private ClientOAuthSessionDetailsService clientOAuthSessionDetailsService;
    @Mock private CriResponseService criResponseService;
    @Mock private AuditService auditService;
    @Captor private ArgumentCaptor<AuditEvent> auditEventArgumentCaptor;
    @InjectMocks private ProcessMobileAppCallbackHandler processMobileAppCallbackHandler;

    @Test
    void shouldReturnNextWhenCriResponseStatusNotError() throws Exception {
        // Arrange
        var requestEvent = buildValidRequestEventWithState(TEST_OAUTH_STATE);
        when(criOAuthSessionService.getCriOauthSessionItem(TEST_OAUTH_STATE))
                .thenReturn(buildValidCriOAuthSessionItem());
        when(clientOAuthSessionDetailsService.getClientOAuthSession(TEST_CLIENT_OAUTH_SESSION_ID))
                .thenReturn(buildValidClientOAuthSessionItem());
        when(criResponseService.getCriResponseItem(TEST_USER_ID, Cri.DCMAW_ASYNC))
                .thenReturn(buildValidCriResponseItem());

        // Act
        var lambdaResponse =
                processMobileAppCallbackHandler.handleRequest(requestEvent, mockContext);
        var journeyResponse =
                OBJECT_MAPPER.readValue(lambdaResponse.getBody(), JourneyResponse.class);

        // Assert
        assertEquals(new JourneyResponse(JOURNEY_NEXT_PATH), journeyResponse);
    }

    @Test
    void shouldReturnCrossBrowserCallbackWhenCallbackRequestMissingIpvSessionId() throws Exception {
        // Arrange
        var requestEvent = buildValidRequestEventWithState(TEST_OAUTH_STATE);
        requestEvent.setHeaders(Map.of());
        var criOAuthSessionItem =
                new CriOAuthSessionItem(
                        TEST_OAUTH_STATE,
                        TEST_CLIENT_OAUTH_SESSION_ID,
                        Cri.DCMAW_ASYNC.toString(),
                        "test_connection",
                        3600);
        when(criOAuthSessionService.getCriOauthSessionItem(TEST_OAUTH_STATE))
                .thenReturn(criOAuthSessionItem);
        var clientOAuthSessionItem = new ClientOAuthSessionItem();
        clientOAuthSessionItem.setUserId(TEST_USER_ID);
        when(clientOAuthSessionDetailsService.getClientOAuthSession(TEST_CLIENT_OAUTH_SESSION_ID))
                .thenReturn(clientOAuthSessionItem);
        var previousIpvSessionItem = new IpvSessionItem();
        previousIpvSessionItem.setIpvSessionId(TEST_IPV_SESSION_ID);
        when(ipvSessionService.getIpvSessionByClientOAuthSessionId(TEST_CLIENT_OAUTH_SESSION_ID))
                .thenReturn(previousIpvSessionItem);

        // Act
        var lambdaResponse =
                processMobileAppCallbackHandler.handleRequest(requestEvent, mockContext);

        // Assert
        var journeyResponse =
                OBJECT_MAPPER.readValue(lambdaResponse.getBody(), JourneyResponse.class);
        assertEquals(
                new JourneyResponse(
                        JOURNEY_BUILD_CLIENT_OAUTH_RESPONSE_PATH, TEST_CLIENT_OAUTH_SESSION_ID),
                journeyResponse);
        verify(auditService).sendAuditEvent(auditEventArgumentCaptor.capture());
        assertEquals(
                AuditEventTypes.IPV_APP_MISSING_CONTEXT,
                auditEventArgumentCaptor.getValue().getEventName());
        assertEquals(TEST_USER_ID, auditEventArgumentCaptor.getValue().getUser().getUserId());
        assertEquals(
                TEST_IPV_SESSION_ID, auditEventArgumentCaptor.getValue().getUser().getSessionId());
    }

    @Test
    void
            shouldReturnCrossBrowserCallbackWhenCallbackRequestMissingIpvSessionIdAndPreviousIpvSessionExpired()
                    throws Exception {
        // Arrange
        var requestEvent = buildValidRequestEventWithState(TEST_OAUTH_STATE);
        requestEvent.setHeaders(Map.of());
        var criOAuthSessionItem =
                new CriOAuthSessionItem(
                        TEST_OAUTH_STATE,
                        TEST_CLIENT_OAUTH_SESSION_ID,
                        Cri.DCMAW_ASYNC.toString(),
                        "test_connection",
                        3600);
        when(criOAuthSessionService.getCriOauthSessionItem(TEST_OAUTH_STATE))
                .thenReturn(criOAuthSessionItem);
        var clientOAuthSessionItem = new ClientOAuthSessionItem();
        clientOAuthSessionItem.setUserId(TEST_USER_ID);
        when(clientOAuthSessionDetailsService.getClientOAuthSession(TEST_CLIENT_OAUTH_SESSION_ID))
                .thenReturn(clientOAuthSessionItem);
        when(ipvSessionService.getIpvSessionByClientOAuthSessionId(TEST_CLIENT_OAUTH_SESSION_ID))
                .thenThrow(
                        new IpvSessionNotFoundException(
                                "The session not found in the database for the supplied clientOAuthSessionId"));

        // Act
        var lambdaResponse =
                processMobileAppCallbackHandler.handleRequest(requestEvent, mockContext);

        // Assert
        var journeyResponse =
                OBJECT_MAPPER.readValue(lambdaResponse.getBody(), JourneyResponse.class);
        assertEquals(
                new JourneyResponse(
                        JOURNEY_BUILD_CLIENT_OAUTH_RESPONSE_PATH, TEST_CLIENT_OAUTH_SESSION_ID),
                journeyResponse);
        verify(auditService).sendAuditEvent(auditEventArgumentCaptor.capture());
        assertEquals(
                AuditEventTypes.IPV_APP_MISSING_CONTEXT,
                auditEventArgumentCaptor.getValue().getEventName());
        assertEquals(TEST_USER_ID, auditEventArgumentCaptor.getValue().getUser().getUserId());
        assertEquals(null, auditEventArgumentCaptor.getValue().getUser().getSessionId());
    }

    @Test
    void shouldReturnErrorWhenCallbackRequestMissingClientOAuthSession() throws Exception {
        // Arrange
        var requestEvent = buildValidRequestEventWithState(TEST_OAUTH_STATE);
        when(criOAuthSessionService.getCriOauthSessionItem(TEST_OAUTH_STATE))
                .thenReturn(buildValidCriOAuthSessionItem());
        when(clientOAuthSessionDetailsService.getClientOAuthSession(TEST_CLIENT_OAUTH_SESSION_ID))
                .thenThrow(new ClientOauthSessionNotFoundException());

        // Act
        var lambdaResponse =
                processMobileAppCallbackHandler.handleRequest(requestEvent, mockContext);
        var journeyResponse =
                OBJECT_MAPPER.readValue(lambdaResponse.getBody(), JourneyErrorResponse.class);

        // Assert
        assertEquals(
                new JourneyErrorResponse(
                        JOURNEY_ERROR_PATH,
                        HttpStatusCode.BAD_REQUEST,
                        ErrorResponse.CLIENT_OAUTH_SESSION_NOT_FOUND),
                journeyResponse);
    }

    @Test
    void shouldReturnErrorWhenMissingOAuthState() throws Exception {
        // Arrange
        var requestEvent = buildValidRequestEventWithState(null);

        // Act
        var lambdaResponse =
                processMobileAppCallbackHandler.handleRequest(requestEvent, mockContext);
        var journeyResponse =
                OBJECT_MAPPER.readValue(lambdaResponse.getBody(), JourneyErrorResponse.class);

        // Assert
        assertEquals(
                new JourneyErrorResponse(
                        JOURNEY_ERROR_PATH,
                        HttpStatusCode.BAD_REQUEST,
                        ErrorResponse.MISSING_OAUTH_STATE),
                journeyResponse);
    }

    @Test
    void shouldReturnErrorWhenCriOAuthSessionNotFound() throws Exception {
        // Arrange
        var requestEvent = buildValidRequestEventWithState(TEST_OAUTH_STATE);
        when(criOAuthSessionService.getCriOauthSessionItem(TEST_OAUTH_STATE)).thenReturn(null);

        // Act
        var lambdaResponse =
                processMobileAppCallbackHandler.handleRequest(requestEvent, mockContext);
        var journeyResponse =
                OBJECT_MAPPER.readValue(lambdaResponse.getBody(), JourneyErrorResponse.class);

        // Assert
        assertEquals(
                new JourneyErrorResponse(
                        JOURNEY_ERROR_PATH,
                        HttpStatusCode.BAD_REQUEST,
                        ErrorResponse.INVALID_OAUTH_STATE),
                journeyResponse);
    }

    @Test
    void shouldReturnErrorWhenCriResponseNotFound() throws Exception {
        // Arrange
        var requestEvent = buildValidRequestEventWithState(TEST_OAUTH_STATE);
        when(clientOAuthSessionDetailsService.getClientOAuthSession(TEST_CLIENT_OAUTH_SESSION_ID))
                .thenReturn(buildValidClientOAuthSessionItem());
        when(criOAuthSessionService.getCriOauthSessionItem(TEST_OAUTH_STATE))
                .thenReturn(buildValidCriOAuthSessionItem());
        when(criResponseService.getCriResponseItem(TEST_USER_ID, Cri.DCMAW_ASYNC)).thenReturn(null);

        // Act
        var lambdaResponse =
                processMobileAppCallbackHandler.handleRequest(requestEvent, mockContext);
        var journeyResponse =
                OBJECT_MAPPER.readValue(lambdaResponse.getBody(), JourneyErrorResponse.class);

        // Assert
        assertEquals(
                new JourneyErrorResponse(
                        JOURNEY_ERROR_PATH,
                        HttpStatusCode.BAD_REQUEST,
                        ErrorResponse.CRI_RESPONSE_ITEM_NOT_FOUND),
                journeyResponse);
    }

    @Test
    void shouldReturnErrorWhenCriResponseStatusError() throws Exception {
        // Arrange
        var requestEvent = buildValidRequestEventWithState(TEST_OAUTH_STATE);
        when(criOAuthSessionService.getCriOauthSessionItem(TEST_OAUTH_STATE))
                .thenReturn(buildValidCriOAuthSessionItem());
        when(clientOAuthSessionDetailsService.getClientOAuthSession(TEST_CLIENT_OAUTH_SESSION_ID))
                .thenReturn(buildValidClientOAuthSessionItem());
        var criResponseItem = buildValidCriResponseItem(CriResponseService.STATUS_ERROR);
        when(criResponseService.getCriResponseItem(TEST_USER_ID, Cri.DCMAW_ASYNC))
                .thenReturn(criResponseItem);

        // Act
        var lambdaResponse =
                processMobileAppCallbackHandler.handleRequest(requestEvent, mockContext);
        var journeyResponse =
                OBJECT_MAPPER.readValue(lambdaResponse.getBody(), JourneyErrorResponse.class);

        // Assert
        assertEquals(
                new JourneyErrorResponse(
                        JOURNEY_ERROR_PATH,
                        HttpStatusCode.INTERNAL_SERVER_ERROR,
                        ErrorResponse.ERROR_MOBILE_APP_RESPONSE_STATUS),
                journeyResponse);
    }

    @Test
    void shouldLogRuntimeExceptionsAndRethrow() throws Exception {
        // Arrange
        when(criOAuthSessionService.getCriOauthSessionItem(TEST_OAUTH_STATE))
                .thenThrow(new RuntimeException("Test error"));
        var requestEvent = buildValidRequestEventWithState(TEST_OAUTH_STATE);

        var logCollector = LogCollector.getLogCollectorFor(ProcessMobileAppCallbackHandler.class);

        // Act
        var thrown =
                assertThrows(
                        Exception.class,
                        () ->
                                processMobileAppCallbackHandler.handleRequest(
                                        requestEvent, mockContext),
                        "Expected handleRequest() to throw, but it didn't");

        // Assert
        assertEquals("Test error", thrown.getMessage());
        var logMessage = logCollector.getLogMessages().get(0);
        assertThat(logMessage, containsString("Unhandled lambda exception"));
        assertThat(logMessage, containsString("Test error"));
    }

    private APIGatewayProxyRequestEvent buildValidRequestEventWithState(String state)
            throws JsonProcessingException {
        var event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of("ipv-session-id", TEST_IPV_SESSION_ID));
        event.setBody(
                OBJECT_MAPPER.writeValueAsString(
                        MobileAppCallbackRequest.builder().state(state).build()));
        return event;
    }

    private CriOAuthSessionItem buildValidCriOAuthSessionItem() {
        return CriOAuthSessionItem.builder()
                .clientOAuthSessionId(TEST_CLIENT_OAUTH_SESSION_ID)
                .build();
    }

    private ClientOAuthSessionItem buildValidClientOAuthSessionItem() {
        return ClientOAuthSessionItem.builder().userId(TEST_USER_ID).build();
    }

    private CriResponseItem buildValidCriResponseItem() {
        return buildValidCriResponseItem(null);
    }

    private CriResponseItem buildValidCriResponseItem(String status) {
        return CriResponseItem.builder()
                .userId(TEST_USER_ID)
                .oauthState(TEST_OAUTH_STATE)
                .status(status)
                .build();
    }
}
