package uk.gov.di.ipv.core.processmobileappcallback;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.http.HttpStatus;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.JourneyErrorResponse;
import uk.gov.di.ipv.core.library.domain.JourneyResponse;
import uk.gov.di.ipv.core.library.exceptions.IpvSessionNotFoundException;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.CriResponseItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.ClientOAuthSessionDetailsService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.CriResponseService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.processmobileappcallback.dto.MobileAppCallbackRequest;

import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.journeyuris.JourneyUris.JOURNEY_ERROR_PATH;
import static uk.gov.di.ipv.core.library.journeyuris.JourneyUris.JOURNEY_NEXT_PATH;

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
    @Mock private ClientOAuthSessionDetailsService clientOAuthSessionDetailsService;
    @Mock private CriResponseService criResponseService;
    @InjectMocks private ProcessMobileAppCallbackHandler processMobileAppCallbackHandler;

    @Test
    void shouldReturnNextWhenCriResponseStatusNotError() throws Exception {
        // Arrange
        var requestEvent = buildValidRequestEventWithState(TEST_OAUTH_STATE);
        when(ipvSessionService.getIpvSession(TEST_IPV_SESSION_ID))
                .thenReturn(buildValidIpvSessionItem());
        when(clientOAuthSessionDetailsService.getClientOAuthSession(TEST_CLIENT_OAUTH_SESSION_ID))
                .thenReturn(buildValidClientOAuthSessionItem());
        when(criResponseService.getCriResponseItemWithState(TEST_USER_ID, TEST_OAUTH_STATE))
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
    void shouldReturnErrorWhenCallbackRequestMissingIpvSessionId() throws Exception {
        // Arrange
        var requestEvent = buildValidRequestEventWithState(TEST_OAUTH_STATE);
        requestEvent.setHeaders(Map.of());

        // Act
        var lambdaResponse =
                processMobileAppCallbackHandler.handleRequest(requestEvent, mockContext);
        var journeyResponse =
                OBJECT_MAPPER.readValue(lambdaResponse.getBody(), JourneyErrorResponse.class);

        // Assert
        assertEquals(
                new JourneyErrorResponse(
                        JOURNEY_ERROR_PATH,
                        HttpStatus.SC_BAD_REQUEST,
                        ErrorResponse.MISSING_IPV_SESSION_ID),
                journeyResponse);
    }

    @Test
    void shouldReturnErrorWhenIpvSessionNotFound() throws Exception {
        // Arrange
        var requestEvent = buildValidRequestEventWithState(TEST_OAUTH_STATE);
        when(ipvSessionService.getIpvSession(TEST_IPV_SESSION_ID))
                .thenThrow(new IpvSessionNotFoundException(""));

        // Act
        var lambdaResponse =
                processMobileAppCallbackHandler.handleRequest(requestEvent, mockContext);
        var journeyResponse =
                OBJECT_MAPPER.readValue(lambdaResponse.getBody(), JourneyErrorResponse.class);

        // Assert
        assertEquals(
                new JourneyErrorResponse(
                        JOURNEY_ERROR_PATH,
                        HttpStatus.SC_BAD_REQUEST,
                        ErrorResponse.IPV_SESSION_NOT_FOUND),
                journeyResponse);
    }

    @Test
    void shouldReturnErrorWhenMissingOAuthState() throws Exception {
        // Arrange
        var requestEvent = buildValidRequestEventWithState(null);
        when(ipvSessionService.getIpvSession(TEST_IPV_SESSION_ID))
                .thenReturn(buildValidIpvSessionItem());
        when(clientOAuthSessionDetailsService.getClientOAuthSession(TEST_CLIENT_OAUTH_SESSION_ID))
                .thenReturn(buildValidClientOAuthSessionItem());

        // Act
        var lambdaResponse =
                processMobileAppCallbackHandler.handleRequest(requestEvent, mockContext);
        var journeyResponse =
                OBJECT_MAPPER.readValue(lambdaResponse.getBody(), JourneyErrorResponse.class);

        // Assert
        assertEquals(
                new JourneyErrorResponse(
                        JOURNEY_ERROR_PATH,
                        HttpStatus.SC_BAD_REQUEST,
                        ErrorResponse.MISSING_OAUTH_STATE),
                journeyResponse);
    }

    @Test
    void shouldReturnErrorWhenCriResponseNotFound() throws Exception {
        // Arrange
        var requestEvent = buildValidRequestEventWithState(TEST_OAUTH_STATE);
        when(ipvSessionService.getIpvSession(TEST_IPV_SESSION_ID))
                .thenReturn(buildValidIpvSessionItem());
        when(clientOAuthSessionDetailsService.getClientOAuthSession(TEST_CLIENT_OAUTH_SESSION_ID))
                .thenReturn(buildValidClientOAuthSessionItem());
        when(criResponseService.getCriResponseItemWithState(TEST_USER_ID, TEST_OAUTH_STATE))
                .thenReturn(Optional.empty());

        // Act
        var lambdaResponse =
                processMobileAppCallbackHandler.handleRequest(requestEvent, mockContext);
        var journeyResponse =
                OBJECT_MAPPER.readValue(lambdaResponse.getBody(), JourneyErrorResponse.class);

        // Assert
        assertEquals(
                new JourneyErrorResponse(
                        JOURNEY_ERROR_PATH,
                        HttpStatus.SC_BAD_REQUEST,
                        ErrorResponse.INVALID_OAUTH_STATE),
                journeyResponse);
    }

    @Test
    void shouldReturnErrorWhenCriResponseStatusError() throws Exception {
        // Arrange
        var requestEvent = buildValidRequestEventWithState(TEST_OAUTH_STATE);
        when(ipvSessionService.getIpvSession(TEST_IPV_SESSION_ID))
                .thenReturn(buildValidIpvSessionItem());
        when(clientOAuthSessionDetailsService.getClientOAuthSession(TEST_CLIENT_OAUTH_SESSION_ID))
                .thenReturn(buildValidClientOAuthSessionItem());
        var criResponseItem = buildValidCriResponseItem(CriResponseService.STATUS_ERROR);
        when(criResponseService.getCriResponseItemWithState(TEST_USER_ID, TEST_OAUTH_STATE))
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
                        HttpStatus.SC_INTERNAL_SERVER_ERROR,
                        ErrorResponse.ERROR_MOBILE_APP_RESPONSE_STATUS),
                journeyResponse);
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

    private IpvSessionItem buildValidIpvSessionItem() {
        var ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setIpvSessionId(TEST_IPV_SESSION_ID);
        ipvSessionItem.setClientOAuthSessionId(TEST_CLIENT_OAUTH_SESSION_ID);
        return ipvSessionItem;
    }

    private ClientOAuthSessionItem buildValidClientOAuthSessionItem() {
        return ClientOAuthSessionItem.builder().userId(TEST_USER_ID).build();
    }

    private Optional<CriResponseItem> buildValidCriResponseItem() {
        return buildValidCriResponseItem(null);
    }

    private Optional<CriResponseItem> buildValidCriResponseItem(String status) {
        return Optional.of(
                CriResponseItem.builder()
                        .userId(TEST_USER_ID)
                        .oauthState(TEST_OAUTH_STATE)
                        .status(status)
                        .build());
    }
}