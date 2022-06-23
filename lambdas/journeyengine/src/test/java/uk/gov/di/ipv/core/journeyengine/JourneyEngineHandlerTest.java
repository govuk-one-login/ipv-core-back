package uk.gov.di.ipv.core.journeyengine;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.oauth2.sdk.OAuth2Error;
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
import uk.gov.di.ipv.core.library.helpers.SecureTokenHelper;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.ConfigurationService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;

import java.io.IOException;
import java.time.Instant;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.ADDRESS_CRI_ID;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.BACKEND_SESSION_TIMEOUT;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.FRAUD_CRI_ID;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.KBV_CRI_ID;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.PASSPORT_CRI_ID;
import static uk.gov.di.ipv.core.library.config.EnvironmentVariable.IPV_JOURNEY_CRI_START_URI;
import static uk.gov.di.ipv.core.library.config.EnvironmentVariable.IPV_JOURNEY_SESSION_END_URI;

@ExtendWith(MockitoExtension.class)
class JourneyEngineHandlerTest {
    private static final String JOURNEY_STEP = "journeyStep";
    private static final String FAIL = "fail";
    private static final String NEXT = "next";
    private static final String ERROR = "error";
    private static final String INVALID_STEP = "invalid-step";
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
        pathParameters.put(JOURNEY_STEP, NEXT);
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
        pathParameters.put(JOURNEY_STEP, NEXT);
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
        pathParameters.put(JOURNEY_STEP, INVALID_STEP);
        event.setPathParameters(pathParameters);

        event.setHeaders(Map.of("ipv-session-id", "1234"));

        IpvSessionItem ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setIpvSessionId(SecureTokenHelper.generate());
        ipvSessionItem.setCreationDateTime(Instant.now().toString());
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
        pathParameters.put(JOURNEY_STEP, NEXT);
        event.setPathParameters(pathParameters);

        event.setHeaders(Map.of("ipv-session-id", "1234"));

        IpvSessionItem ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setIpvSessionId(SecureTokenHelper.generate());
        ipvSessionItem.setCreationDateTime(Instant.now().toString());
        ipvSessionItem.setUserState("INVALID-STATE");

        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);
        when(mockConfigurationService.getSsmParameter(BACKEND_SESSION_TIMEOUT)).thenReturn("7200");

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
        pathParameters.put(JOURNEY_STEP, NEXT);
        event.setPathParameters(pathParameters);

        event.setHeaders(Map.of("ipv-session-id", "1234"));

        IpvSessionItem ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setIpvSessionId(SecureTokenHelper.generate());
        ipvSessionItem.setCreationDateTime(Instant.now().toString());
        ipvSessionItem.setUserState(UserStates.INITIAL_IPV_JOURNEY.toString());

        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);
        when(mockConfigurationService.getSsmParameter(BACKEND_SESSION_TIMEOUT)).thenReturn("7200");

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
        pathParameters.put(JOURNEY_STEP, NEXT);
        event.setPathParameters(pathParameters);

        event.setHeaders(Map.of("ipv-session-id", "1234"));

        IpvSessionItem ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setIpvSessionId(SecureTokenHelper.generate());
        ipvSessionItem.setCreationDateTime(Instant.now().toString());
        ipvSessionItem.setUserState(UserStates.IPV_IDENTITY_START_PAGE.toString());

        mockEnvironmentVariables();
        when(mockConfigurationService.getSsmParameter(BACKEND_SESSION_TIMEOUT)).thenReturn("7200");
        when(mockConfigurationService.getSsmParameter(PASSPORT_CRI_ID)).thenReturn("ukPassport");
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
        pathParameters.put(JOURNEY_STEP, NEXT);
        event.setPathParameters(pathParameters);

        event.setHeaders(Map.of("ipv-session-id", "1234"));

        IpvSessionItem ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setIpvSessionId(SecureTokenHelper.generate());
        ipvSessionItem.setCreationDateTime(Instant.now().toString());
        ipvSessionItem.setUserState(UserStates.CRI_UK_PASSPORT.toString());

        mockEnvironmentVariables();
        when(mockConfigurationService.getSsmParameter(BACKEND_SESSION_TIMEOUT)).thenReturn("7200");
        when(mockConfigurationService.getSsmParameter(ADDRESS_CRI_ID)).thenReturn("address");
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
        pathParameters.put(JOURNEY_STEP, ERROR);
        event.setPathParameters(pathParameters);

        event.setHeaders(Map.of("ipv-session-id", "1234"));

        IpvSessionItem ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setIpvSessionId(SecureTokenHelper.generate());
        ipvSessionItem.setCreationDateTime(Instant.now().toString());
        ipvSessionItem.setUserState(UserStates.CRI_UK_PASSPORT.toString());

        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);
        when(mockConfigurationService.getSsmParameter(BACKEND_SESSION_TIMEOUT)).thenReturn("7200");

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
        pathParameters.put(JOURNEY_STEP, NEXT);
        event.setPathParameters(pathParameters);

        event.setHeaders(Map.of("ipv-session-id", "1234"));

        IpvSessionItem ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setIpvSessionId(SecureTokenHelper.generate());
        ipvSessionItem.setCreationDateTime(Instant.now().toString());
        ipvSessionItem.setUserState(UserStates.CRI_ADDRESS.toString());

        mockEnvironmentVariables();
        when(mockConfigurationService.getSsmParameter(BACKEND_SESSION_TIMEOUT)).thenReturn("7200");
        when(mockConfigurationService.getSsmParameter(FRAUD_CRI_ID)).thenReturn("fraud");
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
        pathParameters.put(JOURNEY_STEP, ERROR);
        event.setPathParameters(pathParameters);

        event.setHeaders(Map.of("ipv-session-id", "1234"));

        IpvSessionItem ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setIpvSessionId(SecureTokenHelper.generate());
        ipvSessionItem.setCreationDateTime(Instant.now().toString());
        ipvSessionItem.setUserState(UserStates.CRI_ADDRESS.toString());

        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);
        when(mockConfigurationService.getSsmParameter(BACKEND_SESSION_TIMEOUT)).thenReturn("7200");

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
        pathParameters.put(JOURNEY_STEP, NEXT);
        event.setPathParameters(pathParameters);

        event.setHeaders(Map.of("ipv-session-id", "1234"));

        IpvSessionItem ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setIpvSessionId(SecureTokenHelper.generate());
        ipvSessionItem.setCreationDateTime(Instant.now().toString());
        ipvSessionItem.setUserState(UserStates.CRI_FRAUD.toString());

        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);
        when(mockConfigurationService.getSsmParameter(BACKEND_SESSION_TIMEOUT)).thenReturn("7200");

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
        pathParameters.put(JOURNEY_STEP, NEXT);
        event.setPathParameters(pathParameters);

        event.setHeaders(Map.of("ipv-session-id", "1234"));

        IpvSessionItem ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setIpvSessionId(SecureTokenHelper.generate());
        ipvSessionItem.setCreationDateTime(Instant.now().toString());
        ipvSessionItem.setUserState(UserStates.PRE_KBV_TRANSITION_PAGE.toString());

        mockEnvironmentVariables();
        when(mockConfigurationService.getSsmParameter(BACKEND_SESSION_TIMEOUT)).thenReturn("7200");
        when(mockConfigurationService.getSsmParameter(KBV_CRI_ID)).thenReturn("kbv");
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
        pathParameters.put(JOURNEY_STEP, ERROR);
        event.setPathParameters(pathParameters);

        event.setHeaders(Map.of("ipv-session-id", "1234"));

        IpvSessionItem ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setIpvSessionId(SecureTokenHelper.generate());
        ipvSessionItem.setCreationDateTime(Instant.now().toString());
        ipvSessionItem.setUserState(UserStates.CRI_FRAUD.toString());

        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);
        when(mockConfigurationService.getSsmParameter(BACKEND_SESSION_TIMEOUT)).thenReturn("7200");

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
        pathParameters.put(JOURNEY_STEP, NEXT);
        event.setPathParameters(pathParameters);

        event.setHeaders(Map.of("ipv-session-id", "1234"));

        IpvSessionItem ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setIpvSessionId(SecureTokenHelper.generate());
        ipvSessionItem.setCreationDateTime(Instant.now().toString());
        ipvSessionItem.setUserState(UserStates.CRI_KBV.toString());

        mockEnvironmentVariables();
        when(mockConfigurationService.getSsmParameter(BACKEND_SESSION_TIMEOUT)).thenReturn("7200");
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
        pathParameters.put(JOURNEY_STEP, ERROR);
        event.setPathParameters(pathParameters);

        event.setHeaders(Map.of("ipv-session-id", "1234"));

        IpvSessionItem ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setIpvSessionId(SecureTokenHelper.generate());
        ipvSessionItem.setCreationDateTime(Instant.now().toString());
        ipvSessionItem.setUserState(UserStates.CRI_KBV.toString());

        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);
        when(mockConfigurationService.getSsmParameter(BACKEND_SESSION_TIMEOUT)).thenReturn("7200");

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
        pathParameters.put(JOURNEY_STEP, NEXT);
        event.setPathParameters(pathParameters);

        event.setHeaders(Map.of("ipv-session-id", "1234"));

        IpvSessionItem ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setIpvSessionId(SecureTokenHelper.generate());
        ipvSessionItem.setCreationDateTime(Instant.now().toString());
        ipvSessionItem.setUserState(UserStates.IPV_SUCCESS_PAGE.toString());

        mockEnvironmentVariables();
        when(mockConfigurationService.getSsmParameter(BACKEND_SESSION_TIMEOUT)).thenReturn("7200");
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
        pathParameters.put(JOURNEY_STEP, NEXT);
        event.setPathParameters(pathParameters);

        event.setHeaders(Map.of("ipv-session-id", "1234"));

        IpvSessionItem ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setIpvSessionId(SecureTokenHelper.generate());
        ipvSessionItem.setCreationDateTime(Instant.now().toString());
        ipvSessionItem.setUserState(UserStates.DEBUG_PAGE.toString());

        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);
        when(mockConfigurationService.getSsmParameter(BACKEND_SESSION_TIMEOUT)).thenReturn("7200");

        APIGatewayProxyResponseEvent response =
                journeyEngineHandler.handleRequest(event, mockContext);
        PageResponse pageResponse = objectMapper.readValue(response.getBody(), PageResponse.class);

        assertEquals(200, response.getStatusCode());
        assertEquals(UserStates.DEBUG_PAGE.value, pageResponse.getPage());
    }

    @Test
    void shouldReturnPYITechnicalPageIfErrorOccursOnDebugJourney() throws IOException {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();

        Map<String, String> pathParameters = new HashMap<>();
        pathParameters.put(JOURNEY_STEP, ERROR);
        event.setPathParameters(pathParameters);

        event.setHeaders(Map.of("ipv-session-id", "1234"));

        IpvSessionItem ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setIpvSessionId(SecureTokenHelper.generate());
        ipvSessionItem.setCreationDateTime(Instant.now().toString());
        ipvSessionItem.setUserState(UserStates.DEBUG_PAGE.toString());

        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);
        when(mockConfigurationService.getSsmParameter(BACKEND_SESSION_TIMEOUT)).thenReturn("7200");

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
    void shouldReturnPYINoMatchPageIfErrorOccursOnDebugJourney() throws IOException {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();

        Map<String, String> pathParameters = new HashMap<>();
        pathParameters.put(JOURNEY_STEP, FAIL);
        event.setPathParameters(pathParameters);

        event.setHeaders(Map.of("ipv-session-id", "1234"));

        IpvSessionItem ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setIpvSessionId(SecureTokenHelper.generate());
        ipvSessionItem.setCreationDateTime(Instant.now().toString());
        ipvSessionItem.setUserState(UserStates.DEBUG_PAGE.toString());

        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);
        when(mockConfigurationService.getSsmParameter(BACKEND_SESSION_TIMEOUT)).thenReturn("7200");

        APIGatewayProxyResponseEvent response =
                journeyEngineHandler.handleRequest(event, mockContext);
        PageResponse pageResponse = objectMapper.readValue(response.getBody(), PageResponse.class);

        ArgumentCaptor<IpvSessionItem> sessionArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(mockIpvSessionService).updateIpvSession(sessionArgumentCaptor.capture());
        assertEquals(
                UserStates.PYI_NO_MATCH.toString(),
                sessionArgumentCaptor.getValue().getUserState());

        assertEquals(200, response.getStatusCode());
        assertEquals(UserStates.PYI_NO_MATCH.value, pageResponse.getPage());
    }

    @Test
    void shouldReturnErrorPageResponseWhenRequired() throws IOException {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();

        Map<String, String> pathParameters = new HashMap<>();
        pathParameters.put(JOURNEY_STEP, NEXT);
        event.setPathParameters(pathParameters);

        event.setHeaders(Map.of("ipv-session-id", "1234"));

        IpvSessionItem ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setIpvSessionId(SecureTokenHelper.generate());
        ipvSessionItem.setCreationDateTime(Instant.now().toString());
        ipvSessionItem.setUserState(UserStates.CRI_ERROR.toString());

        mockEnvironmentVariables();
        when(mockConfigurationService.getSsmParameter(BACKEND_SESSION_TIMEOUT)).thenReturn("7200");
        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);

        APIGatewayProxyResponseEvent response =
                journeyEngineHandler.handleRequest(event, mockContext);
        JourneyResponse journeyResponse =
                objectMapper.readValue(response.getBody(), JourneyResponse.class);

        assertEquals(200, response.getStatusCode());
        assertEquals("/journey/session/end", journeyResponse.getJourney());
    }

    @Test
    void shouldReturnPYINoMatchPageIfPassportCriVCValidationReturnsFail() throws IOException {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();

        Map<String, String> pathParameters = new HashMap<>();
        pathParameters.put(JOURNEY_STEP, FAIL);
        event.setPathParameters(pathParameters);

        event.setHeaders(Map.of("ipv-session-id", "1234"));

        IpvSessionItem ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setIpvSessionId(SecureTokenHelper.generate());
        ipvSessionItem.setCreationDateTime(Instant.now().toString());
        ipvSessionItem.setUserState(UserStates.CRI_UK_PASSPORT.toString());

        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);
        when(mockConfigurationService.getSsmParameter(BACKEND_SESSION_TIMEOUT)).thenReturn("7200");

        APIGatewayProxyResponseEvent response =
                journeyEngineHandler.handleRequest(event, mockContext);
        PageResponse pageResponse = objectMapper.readValue(response.getBody(), PageResponse.class);

        ArgumentCaptor<IpvSessionItem> sessionArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(mockIpvSessionService).updateIpvSession(sessionArgumentCaptor.capture());
        assertEquals(
                UserStates.PYI_NO_MATCH.toString(),
                sessionArgumentCaptor.getValue().getUserState());

        assertEquals(200, response.getStatusCode());
        assertEquals(UserStates.PYI_NO_MATCH.value, pageResponse.getPage());
    }

    @Test
    void shouldReturnPYINoMatchPageIfFraudCriVCValidationReturnsFail() throws IOException {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();

        Map<String, String> pathParameters = new HashMap<>();
        pathParameters.put(JOURNEY_STEP, FAIL);
        event.setPathParameters(pathParameters);

        event.setHeaders(Map.of("ipv-session-id", "1234"));

        IpvSessionItem ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setIpvSessionId(SecureTokenHelper.generate());
        ipvSessionItem.setCreationDateTime(Instant.now().toString());
        ipvSessionItem.setUserState(UserStates.CRI_FRAUD.toString());

        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);
        when(mockConfigurationService.getSsmParameter(BACKEND_SESSION_TIMEOUT)).thenReturn("7200");

        APIGatewayProxyResponseEvent response =
                journeyEngineHandler.handleRequest(event, mockContext);
        PageResponse pageResponse = objectMapper.readValue(response.getBody(), PageResponse.class);

        ArgumentCaptor<IpvSessionItem> sessionArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(mockIpvSessionService).updateIpvSession(sessionArgumentCaptor.capture());
        assertEquals(
                UserStates.PYI_NO_MATCH.toString(),
                sessionArgumentCaptor.getValue().getUserState());

        assertEquals(200, response.getStatusCode());
        assertEquals(UserStates.PYI_NO_MATCH.value, pageResponse.getPage());
    }

    @Test
    void shouldReturnPYIKbvFailPageIfKbvCriVCValidationReturnsFail() throws IOException {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();

        Map<String, String> pathParameters = new HashMap<>();
        pathParameters.put(JOURNEY_STEP, FAIL);
        event.setPathParameters(pathParameters);

        event.setHeaders(Map.of("ipv-session-id", "1234"));

        IpvSessionItem ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setIpvSessionId(SecureTokenHelper.generate());
        ipvSessionItem.setCreationDateTime(Instant.now().toString());
        ipvSessionItem.setUserState(UserStates.CRI_KBV.toString());

        mockEnvironmentVariables();
        when(mockConfigurationService.getSsmParameter(BACKEND_SESSION_TIMEOUT)).thenReturn("7200");
        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);

        APIGatewayProxyResponseEvent response =
                journeyEngineHandler.handleRequest(event, mockContext);
        PageResponse pageResponse = objectMapper.readValue(response.getBody(), PageResponse.class);

        ArgumentCaptor<IpvSessionItem> sessionArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(mockIpvSessionService).updateIpvSession(sessionArgumentCaptor.capture());

        assertEquals(
                UserStates.PYI_KBV_FAIL.toString(),
                sessionArgumentCaptor.getValue().getUserState());

        assertEquals(200, response.getStatusCode());
        assertEquals(UserStates.PYI_KBV_FAIL.value, pageResponse.getPage());
    }

    @Test
    void shouldReturnErrorPageIfSessionHasExpired() throws Exception {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();

        Map<String, String> pathParameters = new HashMap<>();
        pathParameters.put(JOURNEY_STEP, NEXT);
        event.setPathParameters(pathParameters);

        event.setHeaders(Map.of("ipv-session-id", "1234"));

        IpvSessionItem ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setIpvSessionId(SecureTokenHelper.generate());
        ipvSessionItem.setCreationDateTime(Instant.now().minusSeconds(100).toString());
        ipvSessionItem.setUserState(UserStates.CRI_UK_PASSPORT.toString());

        when(mockConfigurationService.getSsmParameter(BACKEND_SESSION_TIMEOUT)).thenReturn("99");
        when(mockIpvSessionService.getIpvSession("1234")).thenReturn(ipvSessionItem);

        APIGatewayProxyResponseEvent response =
                journeyEngineHandler.handleRequest(event, mockContext);
        PageResponse pageResponse = objectMapper.readValue(response.getBody(), PageResponse.class);

        ArgumentCaptor<IpvSessionItem> sessionArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(mockIpvSessionService).updateIpvSession(sessionArgumentCaptor.capture());

        IpvSessionItem capturedIpvSessionItem = sessionArgumentCaptor.getValue();
        assertEquals(
                UserStates.CORE_SESSION_TIMEOUT.toString(), capturedIpvSessionItem.getUserState());
        assertEquals(OAuth2Error.ACCESS_DENIED.getCode(), capturedIpvSessionItem.getErrorCode());
        assertEquals(
                OAuth2Error.ACCESS_DENIED.getDescription(),
                capturedIpvSessionItem.getErrorDescription());

        assertEquals(200, response.getStatusCode());
        assertEquals(UserStates.PYI_TECHNICAL_ERROR_PAGE.value, pageResponse.getPage());
    }

    @Test
    void shouldReturnSessionEndJourneyIfStateIsSessionTimeout() throws Exception {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();

        Map<String, String> pathParameters = new HashMap<>();
        pathParameters.put(JOURNEY_STEP, NEXT);
        event.setPathParameters(pathParameters);

        event.setHeaders(Map.of("ipv-session-id", "1234"));

        IpvSessionItem ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setIpvSessionId(SecureTokenHelper.generate());
        ipvSessionItem.setCreationDateTime(Instant.now().minusSeconds(100).toString());
        ipvSessionItem.setUserState(UserStates.CORE_SESSION_TIMEOUT.toString());

        when(mockConfigurationService.getEnvironmentVariable(IPV_JOURNEY_CRI_START_URI))
                .thenReturn("/journey/session/start");
        when(mockConfigurationService.getEnvironmentVariable(IPV_JOURNEY_SESSION_END_URI))
                .thenReturn("/journey/session/end");
        when(mockIpvSessionService.getIpvSession("1234")).thenReturn(ipvSessionItem);

        APIGatewayProxyResponseEvent response =
                journeyEngineHandler.handleRequest(event, mockContext);
        JourneyResponse journeyResponse =
                objectMapper.readValue(response.getBody(), JourneyResponse.class);

        assertEquals(200, response.getStatusCode());
        assertEquals("/journey/session/end", journeyResponse.getJourney());
    }

    private void mockEnvironmentVariables() {
        when(mockConfigurationService.getEnvironmentVariable(IPV_JOURNEY_CRI_START_URI))
                .thenReturn("/journey/cri/start/");
        when(mockConfigurationService.getEnvironmentVariable(IPV_JOURNEY_SESSION_END_URI))
                .thenReturn("/journey/session/end");
    }
}
