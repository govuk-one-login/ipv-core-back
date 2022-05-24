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
import java.util.Collections;
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
    void shouldReturn400OnMissingParams() throws IOException {

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setPathParameters(Collections.emptyMap());

        APIGatewayProxyResponseEvent response =
                journeyEngineHandler.handleRequest(event, mockContext);

        Map<String, Object> responseBody =
                objectMapper.readValue(response.getBody(), new TypeReference<>() {});
        assertEquals(400, response.getStatusCode());
        assertEquals(
                ErrorResponse.MISSING_JOURNEY_STEP_URL_PATH_PARAM.getCode(),
                responseBody.get("code"));
        assertEquals(
                ErrorResponse.MISSING_JOURNEY_STEP_URL_PATH_PARAM.getMessage(),
                responseBody.get("message"));
    }

    @Test
    void shouldReturn400OnMissingJourneyStepParam() throws IOException {

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setPathParameters(Collections.emptyMap());
        event.setPathParameters(Map.of("InvalidStep", "any"));

        APIGatewayProxyResponseEvent response =
                journeyEngineHandler.handleRequest(event, mockContext);

        Map<String, Object> responseBody =
                objectMapper.readValue(response.getBody(), new TypeReference<>() {});
        assertEquals(400, response.getStatusCode());
        assertEquals(
                ErrorResponse.MISSING_JOURNEY_STEP_URL_PATH_PARAM.getCode(),
                responseBody.get("code"));
        assertEquals(
                ErrorResponse.MISSING_JOURNEY_STEP_URL_PATH_PARAM.getMessage(),
                responseBody.get("message"));
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
        ipvSessionItem.setUserState(UserStates.INITIAL_IPV_JOURNEY.toString());

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
    void shouldReturnIdentityStartPageResponseWhenRequired() throws IOException {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();

        Map<String, String> pathParameters = new HashMap<>();
        pathParameters.put("journeyStep", "next");
        event.setPathParameters(pathParameters);

        event.setHeaders(Map.of("ipv-session-id", "1234"));

        IpvSessionItem ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setIpvSessionId(UUID.randomUUID().toString());
        ipvSessionItem.setCreationDateTime(new Date().toString());
        ipvSessionItem.setUserState(UserStates.INITIAL_IPV_JOURNEY.toString());

        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);

        APIGatewayProxyResponseEvent response =
                journeyEngineHandler.handleRequest(event, mockContext);
        PageResponse pageResponse = objectMapper.readValue(response.getBody(), PageResponse.class);

        ArgumentCaptor<IpvSessionItem> sessionArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(mockIpvSessionService).updateIpvSession(sessionArgumentCaptor.capture());
        assertEquals(
                UserStates.IPV_IDENTITY_START_PAGE.toString(),
                sessionArgumentCaptor.getValue().getUserState());

        assertEquals(200, response.getStatusCode());
        assertEquals(UserStates.IPV_IDENTITY_START_PAGE.value, pageResponse.getPage());
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
        ipvSessionItem.setUserState(UserStates.IPV_IDENTITY_START_PAGE.toString());

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
                UserStates.CRI_UK_PASSPORT.toString(),
                sessionArgumentCaptor.getValue().getUserState());

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
        ipvSessionItem.setUserState(UserStates.CRI_UK_PASSPORT.toString());

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
                UserStates.CRI_ADDRESS.toString(), sessionArgumentCaptor.getValue().getUserState());

        assertEquals(200, response.getStatusCode());
        assertEquals("/journey/cri/start/address", journeyResponse.getJourney());
    }

    @Test
    void shouldReturnCriErrorPageResponseIfPassportCriFails() throws IOException {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();

        Map<String, String> pathParameters = new HashMap<>();
        pathParameters.put("journeyStep", "error");
        event.setPathParameters(pathParameters);

        event.setHeaders(Map.of("ipv-session-id", "1234"));

        IpvSessionItem ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setIpvSessionId(UUID.randomUUID().toString());
        ipvSessionItem.setCreationDateTime(new Date().toString());
        ipvSessionItem.setUserState(UserStates.CRI_UK_PASSPORT.toString());

        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);

        APIGatewayProxyResponseEvent response =
                journeyEngineHandler.handleRequest(event, mockContext);
        PageResponse pageResponse = objectMapper.readValue(response.getBody(), PageResponse.class);

        ArgumentCaptor<IpvSessionItem> sessionArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(mockIpvSessionService).updateIpvSession(sessionArgumentCaptor.capture());
        assertEquals(
                UserStates.CRI_ERROR.toString(), sessionArgumentCaptor.getValue().getUserState());

        assertEquals(200, response.getStatusCode());
        assertEquals(UserStates.PYI_TECHNICAL_ERROR_PAGE.value, pageResponse.getPage());
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
        ipvSessionItem.setUserState(UserStates.CRI_ADDRESS.toString());

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
                UserStates.CRI_FRAUD.toString(), sessionArgumentCaptor.getValue().getUserState());

        assertEquals(200, response.getStatusCode());
        assertEquals("/journey/cri/start/fraud", journeyResponse.getJourney());
    }

    @Test
    void shouldReturnCriErrorPageResponseIfAddressCriFails() throws IOException {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();

        Map<String, String> pathParameters = new HashMap<>();
        pathParameters.put("journeyStep", "error");
        event.setPathParameters(pathParameters);

        event.setHeaders(Map.of("ipv-session-id", "1234"));

        IpvSessionItem ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setIpvSessionId(UUID.randomUUID().toString());
        ipvSessionItem.setCreationDateTime(new Date().toString());
        ipvSessionItem.setUserState(UserStates.CRI_ADDRESS.toString());

        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);

        APIGatewayProxyResponseEvent response =
                journeyEngineHandler.handleRequest(event, mockContext);
        PageResponse pageResponse = objectMapper.readValue(response.getBody(), PageResponse.class);

        ArgumentCaptor<IpvSessionItem> sessionArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(mockIpvSessionService).updateIpvSession(sessionArgumentCaptor.capture());
        assertEquals(
                UserStates.CRI_ERROR.toString(), sessionArgumentCaptor.getValue().getUserState());

        assertEquals(200, response.getStatusCode());
        assertEquals(UserStates.PYI_TECHNICAL_ERROR_PAGE.value, pageResponse.getPage());
    }

    @Test
    void shouldReturnPreKbvTransitionPageResponseWhenRequired() throws IOException {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();

        Map<String, String> pathParameters = new HashMap<>();
        pathParameters.put("journeyStep", "next");
        event.setPathParameters(pathParameters);

        event.setHeaders(Map.of("ipv-session-id", "1234"));

        IpvSessionItem ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setIpvSessionId(UUID.randomUUID().toString());
        ipvSessionItem.setCreationDateTime(new Date().toString());
        ipvSessionItem.setUserState(UserStates.CRI_FRAUD.toString());

        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);

        APIGatewayProxyResponseEvent response =
                journeyEngineHandler.handleRequest(event, mockContext);
        PageResponse pageResponse = objectMapper.readValue(response.getBody(), PageResponse.class);

        ArgumentCaptor<IpvSessionItem> sessionArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(mockIpvSessionService).updateIpvSession(sessionArgumentCaptor.capture());
        assertEquals(
                UserStates.PRE_KBV_TRANSITION_PAGE.toString(),
                sessionArgumentCaptor.getValue().getUserState());

        assertEquals(200, response.getStatusCode());
        assertEquals(UserStates.PRE_KBV_TRANSITION_PAGE.value, pageResponse.getPage());
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
        ipvSessionItem.setUserState(UserStates.PRE_KBV_TRANSITION_PAGE.toString());

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
                UserStates.CRI_KBV.toString(), sessionArgumentCaptor.getValue().getUserState());

        assertEquals(200, response.getStatusCode());
        assertEquals("/journey/cri/start/kbv", journeyResponse.getJourney());
    }

    @Test
    void shouldReturnCriErrorPageResponseIfFraudCriFails() throws IOException {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();

        Map<String, String> pathParameters = new HashMap<>();
        pathParameters.put("journeyStep", "error");
        event.setPathParameters(pathParameters);

        event.setHeaders(Map.of("ipv-session-id", "1234"));

        IpvSessionItem ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setIpvSessionId(UUID.randomUUID().toString());
        ipvSessionItem.setCreationDateTime(new Date().toString());
        ipvSessionItem.setUserState(UserStates.CRI_FRAUD.toString());

        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);

        APIGatewayProxyResponseEvent response =
                journeyEngineHandler.handleRequest(event, mockContext);
        PageResponse pageResponse = objectMapper.readValue(response.getBody(), PageResponse.class);

        ArgumentCaptor<IpvSessionItem> sessionArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(mockIpvSessionService).updateIpvSession(sessionArgumentCaptor.capture());
        assertEquals(
                UserStates.CRI_ERROR.toString(), sessionArgumentCaptor.getValue().getUserState());

        assertEquals(200, response.getStatusCode());
        assertEquals(UserStates.PYI_TECHNICAL_ERROR_PAGE.value, pageResponse.getPage());
    }

    @Test
    void shouldReturnIpvSuccessPageResponseWhenRequired() throws IOException {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();

        Map<String, String> pathParameters = new HashMap<>();
        pathParameters.put("journeyStep", "next");
        event.setPathParameters(pathParameters);

        event.setHeaders(Map.of("ipv-session-id", "1234"));

        IpvSessionItem ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setIpvSessionId(UUID.randomUUID().toString());
        ipvSessionItem.setCreationDateTime(new Date().toString());
        ipvSessionItem.setUserState(UserStates.CRI_KBV.toString());

        when(mockConfigurationService.getIpvJourneyCriStartUri()).thenReturn("/journey/cri/start/");
        when(mockConfigurationService.getIpvJourneySessionEnd()).thenReturn("/journey/session/end");
        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);

        APIGatewayProxyResponseEvent response =
                journeyEngineHandler.handleRequest(event, mockContext);
        PageResponse pageResponse = objectMapper.readValue(response.getBody(), PageResponse.class);

        ArgumentCaptor<IpvSessionItem> sessionArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(mockIpvSessionService).updateIpvSession(sessionArgumentCaptor.capture());

        assertEquals(
                UserStates.IPV_SUCCESS_PAGE.toString(),
                sessionArgumentCaptor.getValue().getUserState());

        assertEquals(200, response.getStatusCode());
        assertEquals(UserStates.IPV_SUCCESS_PAGE.value, pageResponse.getPage());
    }

    @Test
    void shouldReturnCriErrorPageResponseIfKbvCriFails() throws IOException {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();

        Map<String, String> pathParameters = new HashMap<>();
        pathParameters.put("journeyStep", "error");
        event.setPathParameters(pathParameters);

        event.setHeaders(Map.of("ipv-session-id", "1234"));

        IpvSessionItem ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setIpvSessionId(UUID.randomUUID().toString());
        ipvSessionItem.setCreationDateTime(new Date().toString());
        ipvSessionItem.setUserState(UserStates.CRI_KBV.toString());

        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);

        APIGatewayProxyResponseEvent response =
                journeyEngineHandler.handleRequest(event, mockContext);
        PageResponse pageResponse = objectMapper.readValue(response.getBody(), PageResponse.class);

        ArgumentCaptor<IpvSessionItem> sessionArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(mockIpvSessionService).updateIpvSession(sessionArgumentCaptor.capture());
        assertEquals(
                UserStates.CRI_ERROR.toString(), sessionArgumentCaptor.getValue().getUserState());

        assertEquals(200, response.getStatusCode());
        assertEquals(UserStates.PYI_TECHNICAL_ERROR_PAGE.value, pageResponse.getPage());
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
        ipvSessionItem.setUserState(UserStates.IPV_SUCCESS_PAGE.toString());

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
        ipvSessionItem.setUserState(UserStates.DEBUG_PAGE.toString());

        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);

        APIGatewayProxyResponseEvent response =
                journeyEngineHandler.handleRequest(event, mockContext);
        PageResponse pageResponse = objectMapper.readValue(response.getBody(), PageResponse.class);

        assertEquals(200, response.getStatusCode());
        assertEquals(UserStates.DEBUG_PAGE.value, pageResponse.getPage());
    }

    @Test
    void shouldReturnErrorPageResponseWhenRequired() throws IOException {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();

        Map<String, String> pathParameters = new HashMap<>();
        pathParameters.put("journeyStep", "next");
        event.setPathParameters(pathParameters);

        event.setHeaders(Map.of("ipv-session-id", "1234"));

        IpvSessionItem ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setIpvSessionId(UUID.randomUUID().toString());
        ipvSessionItem.setCreationDateTime(new Date().toString());
        ipvSessionItem.setUserState(UserStates.CRI_ERROR.toString());

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
    void shouldReturnCriErrorPageResponseIfPassportCriReturnsFail() throws IOException {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();

        Map<String, String> pathParameters = new HashMap<>();
        pathParameters.put("journeyStep", "fail");
        event.setPathParameters(pathParameters);

        event.setHeaders(Map.of("ipv-session-id", "1234"));

        IpvSessionItem ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setIpvSessionId(UUID.randomUUID().toString());
        ipvSessionItem.setCreationDateTime(new Date().toString());
        ipvSessionItem.setUserState(UserStates.CRI_UK_PASSPORT.toString());

        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);

        APIGatewayProxyResponseEvent response =
                journeyEngineHandler.handleRequest(event, mockContext);
        PageResponse pageResponse = objectMapper.readValue(response.getBody(), PageResponse.class);

        ArgumentCaptor<IpvSessionItem> sessionArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(mockIpvSessionService).updateIpvSession(sessionArgumentCaptor.capture());
        assertEquals(
                UserStates.CRI_ERROR.toString(), sessionArgumentCaptor.getValue().getUserState());

        assertEquals(200, response.getStatusCode());
        assertEquals(UserStates.PYI_TECHNICAL_ERROR_PAGE.value, pageResponse.getPage());
    }
}
