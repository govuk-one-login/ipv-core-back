package uk.gov.di.ipv.core.journeyengine;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.journeyengine.domain.PageResponse;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.JourneyResponse;
import uk.gov.di.ipv.core.library.domain.UserStates;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.ConfigurationService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;

import java.io.IOException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class JourneyEngineHandlerTest {
    @Mock private Context mockContext;
    @Mock private IpvSessionService mockIpvSessionService;
    @Mock private ConfigurationService mockConfigurationService;

    private JourneyEngineHandler journeyEngineHandler;

    private final ObjectMapper objectMapper = new ObjectMapper();

    @BeforeEach
    void setUp() {
        journeyEngineHandler =
                new JourneyEngineHandler(mockIpvSessionService, mockConfigurationService);
    }

    @Test
    void shouldReturn400OnMissingIpvSessionIdHeader() throws IOException {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();

        Map<String, String> pathParameters = new HashMap<>();
        pathParameters.put("journeyStep", "next");
        event.setPathParameters(pathParameters);

        APIGatewayProxyResponseEvent response =
                journeyEngineHandler.handleRequest(event, mockContext);
        Map<String, Object> responseBody =
                objectMapper.readValue(response.getBody(), new TypeReference<>() {});

        assertEquals(400, response.getStatusCode());
        assertEquals(ErrorResponse.MISSING_IPV_SESSION_ID.getCode(), responseBody.get("code"));
        assertEquals(
                ErrorResponse.MISSING_IPV_SESSION_ID.getMessage(), responseBody.get("message"));
    }

    @Test
    void shouldReturn400WhenInvalidSessionIdProvided() throws IOException {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();

        Map<String, String> pathParameters = new HashMap<>();
        pathParameters.put("journeyStep", "next");
        event.setPathParameters(pathParameters);

        event.setHeaders(Map.of("ipv-session-id", "1234"));

        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(null);

        APIGatewayProxyResponseEvent response =
                journeyEngineHandler.handleRequest(event, mockContext);
        Map<String, Object> responseBody =
                objectMapper.readValue(response.getBody(), new TypeReference<>() {});

        assertEquals(400, response.getStatusCode());
        assertEquals(ErrorResponse.INVALID_SESSION_ID.getCode(), responseBody.get("code"));
        assertEquals(ErrorResponse.INVALID_SESSION_ID.getMessage(), responseBody.get("message"));
    }

    @Test
    void shouldReturn500WhenUnknownJourneyEngineStepProvided() throws IOException {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();

        Map<String, String> pathParameters = new HashMap<>();
        pathParameters.put("journeyStep", "invalid-step");
        event.setPathParameters(pathParameters);

        event.setHeaders(Map.of("ipv-session-id", "1234"));

        IpvSessionItem ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setIpvSessionId(UUID.randomUUID().toString());
        ipvSessionItem.setCreationDateTime(new Date().toString());
        ipvSessionItem.setUserState(UserStates.INITIAL_IPV_JOURNEY.value);

        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);

        APIGatewayProxyResponseEvent response =
                journeyEngineHandler.handleRequest(event, mockContext);
        Map<String, Object> responseBody =
                objectMapper.readValue(response.getBody(), new TypeReference<>() {});

        assertEquals(500, response.getStatusCode());
        assertEquals(ErrorResponse.FAILED_JOURNEY_ENGINE_STEP.getCode(), responseBody.get("code"));
        assertEquals(
                ErrorResponse.FAILED_JOURNEY_ENGINE_STEP.getMessage(), responseBody.get("message"));
    }

    @Test
    void shouldReturn500WhenUserIsInUnknownState() throws IOException {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();

        Map<String, String> pathParameters = new HashMap<>();
        pathParameters.put("journeyStep", "next");
        event.setPathParameters(pathParameters);

        event.setHeaders(Map.of("ipv-session-id", "1234"));

        IpvSessionItem ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setIpvSessionId(UUID.randomUUID().toString());
        ipvSessionItem.setCreationDateTime(new Date().toString());
        ipvSessionItem.setUserState("INVALID-STATE");

        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);

        APIGatewayProxyResponseEvent response =
                journeyEngineHandler.handleRequest(event, mockContext);
        Map<String, Object> responseBody =
                objectMapper.readValue(response.getBody(), new TypeReference<>() {});

        assertEquals(500, response.getStatusCode());
        assertEquals(ErrorResponse.FAILED_JOURNEY_ENGINE_STEP.getCode(), responseBody.get("code"));
        assertEquals(
                ErrorResponse.FAILED_JOURNEY_ENGINE_STEP.getMessage(), responseBody.get("message"));
    }

    @Test
    void shouldReturn1stTransitionPageResponseWhenRequired() throws IOException {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();

        Map<String, String> pathParameters = new HashMap<>();
        pathParameters.put("journeyStep", "next");
        event.setPathParameters(pathParameters);

        event.setHeaders(Map.of("ipv-session-id", "1234"));

        IpvSessionItem ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setIpvSessionId(UUID.randomUUID().toString());
        ipvSessionItem.setCreationDateTime(new Date().toString());
        ipvSessionItem.setUserState(UserStates.INITIAL_IPV_JOURNEY.value);

        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);

        APIGatewayProxyResponseEvent response =
                journeyEngineHandler.handleRequest(event, mockContext);
        PageResponse pageResponse = objectMapper.readValue(response.getBody(), PageResponse.class);

        ArgumentCaptor<IpvSessionItem> sessionArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(mockIpvSessionService).updateIpvSession(sessionArgumentCaptor.capture());
        assertEquals(
                UserStates.TRANSITION_PAGE_1.value,
                sessionArgumentCaptor.getValue().getUserState());

        assertEquals(200, response.getStatusCode());
        assertEquals("core:transitionPage1", pageResponse.getPage());
    }

    @Test
    void shouldReturnCriUkPassportJourneyResponseWhenRequired() throws IOException {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();

        Map<String, String> pathParameters = new HashMap<>();
        pathParameters.put("journeyStep", "next");
        event.setPathParameters(pathParameters);

        event.setHeaders(Map.of("ipv-session-id", "1234"));

        IpvSessionItem ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setIpvSessionId(UUID.randomUUID().toString());
        ipvSessionItem.setCreationDateTime(new Date().toString());
        ipvSessionItem.setUserState(UserStates.TRANSITION_PAGE_1.value);

        when(mockConfigurationService.getIpvJourneyCriStartUri()).thenReturn("/journey/cri/start/");
        when(mockConfigurationService.getIpvJourneySessionEnd()).thenReturn("/journey/session/end");
        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);

        APIGatewayProxyResponseEvent response =
                journeyEngineHandler.handleRequest(event, mockContext);
        JourneyResponse journeyResponse =
                objectMapper.readValue(response.getBody(), JourneyResponse.class);

        ArgumentCaptor<IpvSessionItem> sessionArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(mockIpvSessionService).updateIpvSession(sessionArgumentCaptor.capture());
        assertEquals(
                UserStates.CRI_UK_PASSPORT.value, sessionArgumentCaptor.getValue().getUserState());

        assertEquals(200, response.getStatusCode());
        assertEquals("/journey/cri/start/ukPassport", journeyResponse.getJourney());
    }

    @Test
    void shouldReturnCriAddressJourneyResponseWhenRequired() throws IOException {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();

        Map<String, String> pathParameters = new HashMap<>();
        pathParameters.put("journeyStep", "next");
        event.setPathParameters(pathParameters);

        event.setHeaders(Map.of("ipv-session-id", "1234"));

        IpvSessionItem ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setIpvSessionId(UUID.randomUUID().toString());
        ipvSessionItem.setCreationDateTime(new Date().toString());
        ipvSessionItem.setUserState(UserStates.CRI_UK_PASSPORT.value);

        when(mockConfigurationService.getIpvJourneyCriStartUri()).thenReturn("/journey/cri/start/");
        when(mockConfigurationService.getIpvJourneySessionEnd()).thenReturn("/journey/session/end");
        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);

        APIGatewayProxyResponseEvent response =
                journeyEngineHandler.handleRequest(event, mockContext);
        JourneyResponse journeyResponse =
                objectMapper.readValue(response.getBody(), JourneyResponse.class);

        ArgumentCaptor<IpvSessionItem> sessionArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(mockIpvSessionService).updateIpvSession(sessionArgumentCaptor.capture());
        assertEquals(UserStates.CRI_ADDRESS.value, sessionArgumentCaptor.getValue().getUserState());

        assertEquals(200, response.getStatusCode());
        assertEquals("/journey/cri/start/address", journeyResponse.getJourney());
    }

    @Test
    void shouldReturnCriKbvJourneyResponseWhenRequired() throws IOException {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();

        Map<String, String> pathParameters = new HashMap<>();
        pathParameters.put("journeyStep", "next");
        event.setPathParameters(pathParameters);

        event.setHeaders(Map.of("ipv-session-id", "1234"));

        IpvSessionItem ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setIpvSessionId(UUID.randomUUID().toString());
        ipvSessionItem.setCreationDateTime(new Date().toString());
        ipvSessionItem.setUserState(UserStates.CRI_ADDRESS.value);

        when(mockConfigurationService.getIpvJourneyCriStartUri()).thenReturn("/journey/cri/start/");
        when(mockConfigurationService.getIpvJourneySessionEnd()).thenReturn("/journey/session/end");
        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);

        APIGatewayProxyResponseEvent response =
                journeyEngineHandler.handleRequest(event, mockContext);
        JourneyResponse journeyResponse =
                objectMapper.readValue(response.getBody(), JourneyResponse.class);

        ArgumentCaptor<IpvSessionItem> sessionArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(mockIpvSessionService).updateIpvSession(sessionArgumentCaptor.capture());
        assertEquals(UserStates.CRI_KBV.value, sessionArgumentCaptor.getValue().getUserState());

        assertEquals(200, response.getStatusCode());
        assertEquals("/journey/cri/start/kbv", journeyResponse.getJourney());
    }

    @Test
    void shouldReturn2ndTransitionPageResponseWhenRequired() throws IOException {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();

        Map<String, String> pathParameters = new HashMap<>();
        pathParameters.put("journeyStep", "next");
        event.setPathParameters(pathParameters);

        event.setHeaders(Map.of("ipv-session-id", "1234"));

        IpvSessionItem ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setIpvSessionId(UUID.randomUUID().toString());
        ipvSessionItem.setCreationDateTime(new Date().toString());
        ipvSessionItem.setUserState(UserStates.CRI_KBV.value);

        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);

        APIGatewayProxyResponseEvent response =
                journeyEngineHandler.handleRequest(event, mockContext);
        PageResponse pageResponse = objectMapper.readValue(response.getBody(), PageResponse.class);

        ArgumentCaptor<IpvSessionItem> sessionArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(mockIpvSessionService).updateIpvSession(sessionArgumentCaptor.capture());
        assertEquals(
                UserStates.TRANSITION_PAGE_2.value,
                sessionArgumentCaptor.getValue().getUserState());

        assertEquals(200, response.getStatusCode());
        assertEquals(UserStates.TRANSITION_PAGE_2.value, pageResponse.getPage());
    }

    @Test
    void shouldReturnCriFraudJourneyResponseWhenRequired() throws IOException {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();

        Map<String, String> pathParameters = new HashMap<>();
        pathParameters.put("journeyStep", "next");
        event.setPathParameters(pathParameters);

        event.setHeaders(Map.of("ipv-session-id", "1234"));

        IpvSessionItem ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setIpvSessionId(UUID.randomUUID().toString());
        ipvSessionItem.setCreationDateTime(new Date().toString());
        ipvSessionItem.setUserState(UserStates.TRANSITION_PAGE_2.value);

        when(mockConfigurationService.getIpvJourneyCriStartUri()).thenReturn("/journey/cri/start/");
        when(mockConfigurationService.getIpvJourneySessionEnd()).thenReturn("/journey/session/end");
        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);

        APIGatewayProxyResponseEvent response =
                journeyEngineHandler.handleRequest(event, mockContext);
        JourneyResponse journeyResponse =
                objectMapper.readValue(response.getBody(), JourneyResponse.class);

        ArgumentCaptor<IpvSessionItem> sessionArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(mockIpvSessionService).updateIpvSession(sessionArgumentCaptor.capture());
        assertEquals(UserStates.CRI_FRAUD.value, sessionArgumentCaptor.getValue().getUserState());

        assertEquals(200, response.getStatusCode());
        assertEquals("/journey/cri/start/fraud", journeyResponse.getJourney());
    }

    @Test
    void shouldReturnCriActivityHistoryJourneyResponseWhenRequired() throws IOException {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();

        Map<String, String> pathParameters = new HashMap<>();
        pathParameters.put("journeyStep", "next");
        event.setPathParameters(pathParameters);

        event.setHeaders(Map.of("ipv-session-id", "1234"));

        IpvSessionItem ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setIpvSessionId(UUID.randomUUID().toString());
        ipvSessionItem.setCreationDateTime(new Date().toString());
        ipvSessionItem.setUserState(UserStates.CRI_FRAUD.value);

        when(mockConfigurationService.getIpvJourneyCriStartUri()).thenReturn("/journey/cri/start/");
        when(mockConfigurationService.getIpvJourneySessionEnd()).thenReturn("/journey/session/end");
        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);

        APIGatewayProxyResponseEvent response =
                journeyEngineHandler.handleRequest(event, mockContext);
        JourneyResponse journeyResponse =
                objectMapper.readValue(response.getBody(), JourneyResponse.class);

        ArgumentCaptor<IpvSessionItem> sessionArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(mockIpvSessionService).updateIpvSession(sessionArgumentCaptor.capture());
        assertEquals(
                UserStates.CRI_ACTIVITY_HISTORY.value,
                sessionArgumentCaptor.getValue().getUserState());

        assertEquals(200, response.getStatusCode());
        assertEquals("/journey/cri/start/activityHistory", journeyResponse.getJourney());
    }

    @Test
    void shouldReturnEndSessionJourneyResponseWhenRequired() throws IOException {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();

        Map<String, String> pathParameters = new HashMap<>();
        pathParameters.put("journeyStep", "next");
        event.setPathParameters(pathParameters);

        event.setHeaders(Map.of("ipv-session-id", "1234"));

        IpvSessionItem ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setIpvSessionId(UUID.randomUUID().toString());
        ipvSessionItem.setCreationDateTime(new Date().toString());
        ipvSessionItem.setUserState(UserStates.CRI_ACTIVITY_HISTORY.value);

        when(mockConfigurationService.getIpvJourneyCriStartUri()).thenReturn("/journey/cri/start/");
        when(mockConfigurationService.getIpvJourneySessionEnd()).thenReturn("/journey/session/end");
        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);

        APIGatewayProxyResponseEvent response =
                journeyEngineHandler.handleRequest(event, mockContext);
        JourneyResponse journeyResponse =
                objectMapper.readValue(response.getBody(), JourneyResponse.class);

        assertEquals(200, response.getStatusCode());
        assertEquals("/journey/session/end", journeyResponse.getJourney());
    }

    @Test
    void shouldReturnDebugPageResponseWhenRequired() throws IOException {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();

        Map<String, String> pathParameters = new HashMap<>();
        pathParameters.put("journeyStep", "next");
        event.setPathParameters(pathParameters);

        event.setHeaders(Map.of("ipv-session-id", "1234"));

        IpvSessionItem ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setIpvSessionId(UUID.randomUUID().toString());
        ipvSessionItem.setCreationDateTime(new Date().toString());
        ipvSessionItem.setUserState(UserStates.DEBUG_PAGE.value);

        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);

        APIGatewayProxyResponseEvent response =
                journeyEngineHandler.handleRequest(event, mockContext);
        PageResponse pageResponse = objectMapper.readValue(response.getBody(), PageResponse.class);

        assertEquals(200, response.getStatusCode());
        assertEquals(UserStates.DEBUG_PAGE.value, pageResponse.getPage());
    }
}
