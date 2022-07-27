package uk.gov.di.ipv.core.processjourneystep;

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
import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.UserStates;
import uk.gov.di.ipv.core.library.helpers.SecureTokenHelper;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.ConfigurationService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.processjourneystep.statemachine.StateMachine;
import uk.gov.di.ipv.core.processjourneystep.statemachine.StateMachineInitializer;

import java.io.IOException;
import java.time.Instant;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.BACKEND_SESSION_TIMEOUT;

@ExtendWith(MockitoExtension.class)
class ProcessJourneyStepHandlerTest {
    private static final String JOURNEY_STEP = "journeyStep";
    private static final String FAIL = "fail";
    private static final String NEXT = "next";
    private static final String ERROR = "error";
    private static final String INVALID_STEP = "invalid-step";
    @Mock private Context mockContext;
    @Mock private IpvSessionService mockIpvSessionService;
    @Mock private ConfigurationService mockConfigurationService;

    private ProcessJourneyStepHandler processJourneyStepHandler;
    private final ObjectMapper objectMapper = new ObjectMapper();

    @BeforeEach
    void setUp() throws IOException {
        StateMachine stateMachine = new StateMachine(new StateMachineInitializer());
        processJourneyStepHandler =
                new ProcessJourneyStepHandler(
                        stateMachine, mockIpvSessionService, mockConfigurationService);
    }

    @Test
    void shouldReturn400OnMissingParams() throws IOException {

        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of("ipv-session-id", "1234"));
        event.setPathParameters(Collections.emptyMap());

        APIGatewayProxyResponseEvent response =
                processJourneyStepHandler.handleRequest(event, mockContext);

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
        event.setHeaders(Map.of("ipv-session-id", "1234"));
        event.setPathParameters(Collections.emptyMap());
        event.setPathParameters(Map.of("InvalidStep", "any"));

        APIGatewayProxyResponseEvent response =
                processJourneyStepHandler.handleRequest(event, mockContext);

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
                processJourneyStepHandler.handleRequest(event, mockContext);
        Map<String, Object> responseBody =
                objectMapper.readValue(response.getBody(), new TypeReference<>() {});

        assertEquals(400, response.getStatusCode());
        assertEquals(ErrorResponse.MISSING_IPV_SESSION_ID.getCode(), responseBody.get("error"));
        assertEquals(
                ErrorResponse.MISSING_IPV_SESSION_ID.getMessage(),
                responseBody.get("error_description"));
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
                processJourneyStepHandler.handleRequest(event, mockContext);
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
        when(mockConfigurationService.getSsmParameter(BACKEND_SESSION_TIMEOUT)).thenReturn("7200");

        APIGatewayProxyResponseEvent response =
                processJourneyStepHandler.handleRequest(event, mockContext);
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
                processJourneyStepHandler.handleRequest(event, mockContext);
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
                processJourneyStepHandler.handleRequest(event, mockContext);
        Map<String, String> pageResponse =
                objectMapper.readValue(response.getBody(), new TypeReference<>() {});

        ArgumentCaptor<IpvSessionItem> sessionArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(mockIpvSessionService).updateIpvSession(sessionArgumentCaptor.capture());
        assertEquals(
                UserStates.IPV_IDENTITY_START_PAGE.toString(),
                sessionArgumentCaptor.getValue().getUserState());

        assertEquals(200, response.getStatusCode());
        assertEquals(UserStates.IPV_IDENTITY_START_PAGE.value, pageResponse.get("page"));
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

        when(mockConfigurationService.getSsmParameter(ConfigurationVariable.PASSPORT_CRI_ID))
                .thenReturn("ukPassport");
        when(mockConfigurationService.getSsmParameter(BACKEND_SESSION_TIMEOUT)).thenReturn("7200");
        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);

        APIGatewayProxyResponseEvent response =
                processJourneyStepHandler.handleRequest(event, mockContext);
        Map<String, String> criResponse =
                objectMapper.readValue(response.getBody(), new TypeReference<>() {});

        ArgumentCaptor<IpvSessionItem> sessionArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(mockIpvSessionService).updateIpvSession(sessionArgumentCaptor.capture());
        assertEquals(
                UserStates.CRI_UK_PASSPORT.toString(),
                sessionArgumentCaptor.getValue().getUserState());

        assertEquals(200, response.getStatusCode());
        assertEquals("/journey/cri/start/ukPassport", criResponse.get("journey"));
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

        when(mockConfigurationService.getSsmParameter(ConfigurationVariable.ADDRESS_CRI_ID))
                .thenReturn("address");
        when(mockConfigurationService.getSsmParameter(BACKEND_SESSION_TIMEOUT)).thenReturn("7200");
        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);

        APIGatewayProxyResponseEvent response =
                processJourneyStepHandler.handleRequest(event, mockContext);
        Map<String, String> criResponse =
                objectMapper.readValue(response.getBody(), new TypeReference<>() {});

        ArgumentCaptor<IpvSessionItem> sessionArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(mockIpvSessionService).updateIpvSession(sessionArgumentCaptor.capture());
        assertEquals(
                UserStates.CRI_ADDRESS.toString(), sessionArgumentCaptor.getValue().getUserState());

        assertEquals(200, response.getStatusCode());
        assertEquals("/journey/cri/start/address", criResponse.get("journey"));
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
                processJourneyStepHandler.handleRequest(event, mockContext);
        Map<String, String> pageResponse =
                objectMapper.readValue(response.getBody(), new TypeReference<>() {});

        ArgumentCaptor<IpvSessionItem> sessionArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(mockIpvSessionService).updateIpvSession(sessionArgumentCaptor.capture());
        assertEquals(
                UserStates.CRI_ERROR.toString(), sessionArgumentCaptor.getValue().getUserState());

        assertEquals(200, response.getStatusCode());
        assertEquals(UserStates.PYI_TECHNICAL_ERROR_PAGE.value, pageResponse.get("page"));
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

        when(mockConfigurationService.getSsmParameter(ConfigurationVariable.FRAUD_CRI_ID))
                .thenReturn("fraud");
        when(mockConfigurationService.getSsmParameter(BACKEND_SESSION_TIMEOUT)).thenReturn("7200");
        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);

        APIGatewayProxyResponseEvent response =
                processJourneyStepHandler.handleRequest(event, mockContext);
        Map<String, String> criResponse =
                objectMapper.readValue(response.getBody(), new TypeReference<>() {});

        ArgumentCaptor<IpvSessionItem> sessionArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(mockIpvSessionService).updateIpvSession(sessionArgumentCaptor.capture());
        assertEquals(
                UserStates.CRI_FRAUD.toString(), sessionArgumentCaptor.getValue().getUserState());

        assertEquals(200, response.getStatusCode());
        assertEquals("/journey/cri/start/fraud", criResponse.get("journey"));
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
                processJourneyStepHandler.handleRequest(event, mockContext);
        Map<String, String> pageResponse =
                objectMapper.readValue(response.getBody(), new TypeReference<>() {});

        ArgumentCaptor<IpvSessionItem> sessionArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(mockIpvSessionService).updateIpvSession(sessionArgumentCaptor.capture());
        assertEquals(
                UserStates.CRI_ERROR.toString(), sessionArgumentCaptor.getValue().getUserState());

        assertEquals(200, response.getStatusCode());
        assertEquals(UserStates.PYI_TECHNICAL_ERROR_PAGE.value, pageResponse.get("page"));
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
                processJourneyStepHandler.handleRequest(event, mockContext);
        Map<String, String> pageResponse =
                objectMapper.readValue(response.getBody(), new TypeReference<>() {});

        ArgumentCaptor<IpvSessionItem> sessionArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(mockIpvSessionService).updateIpvSession(sessionArgumentCaptor.capture());
        assertEquals(
                UserStates.PRE_KBV_TRANSITION_PAGE.toString(),
                sessionArgumentCaptor.getValue().getUserState());

        assertEquals(200, response.getStatusCode());
        assertEquals(UserStates.PRE_KBV_TRANSITION_PAGE.value, pageResponse.get("page"));
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

        when(mockConfigurationService.getSsmParameter(BACKEND_SESSION_TIMEOUT)).thenReturn("7200");
        when(mockConfigurationService.getSsmParameter(ConfigurationVariable.KBV_CRI_ID))
                .thenReturn("kbv");
        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);

        APIGatewayProxyResponseEvent response =
                processJourneyStepHandler.handleRequest(event, mockContext);
        Map<String, String> criResponse =
                objectMapper.readValue(response.getBody(), new TypeReference<>() {});

        ArgumentCaptor<IpvSessionItem> sessionArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(mockIpvSessionService).updateIpvSession(sessionArgumentCaptor.capture());
        assertEquals(
                UserStates.CRI_KBV.toString(), sessionArgumentCaptor.getValue().getUserState());

        assertEquals(200, response.getStatusCode());
        assertEquals("/journey/cri/start/kbv", criResponse.get("journey"));
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
                processJourneyStepHandler.handleRequest(event, mockContext);
        Map<String, String> pageResponse =
                objectMapper.readValue(response.getBody(), new TypeReference<>() {});

        ArgumentCaptor<IpvSessionItem> sessionArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(mockIpvSessionService).updateIpvSession(sessionArgumentCaptor.capture());
        assertEquals(
                UserStates.CRI_ERROR.toString(), sessionArgumentCaptor.getValue().getUserState());

        assertEquals(200, response.getStatusCode());
        assertEquals(UserStates.PYI_TECHNICAL_ERROR_PAGE.value, pageResponse.get("page"));
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

        when(mockConfigurationService.getSsmParameter(BACKEND_SESSION_TIMEOUT)).thenReturn("7200");
        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);

        APIGatewayProxyResponseEvent response =
                processJourneyStepHandler.handleRequest(event, mockContext);
        Map<String, String> pageResponse =
                objectMapper.readValue(response.getBody(), new TypeReference<>() {});

        ArgumentCaptor<IpvSessionItem> sessionArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(mockIpvSessionService).updateIpvSession(sessionArgumentCaptor.capture());

        assertEquals(
                UserStates.IPV_SUCCESS_PAGE.toString(),
                sessionArgumentCaptor.getValue().getUserState());

        assertEquals(200, response.getStatusCode());
        assertEquals(UserStates.IPV_SUCCESS_PAGE.value, pageResponse.get("page"));
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
                processJourneyStepHandler.handleRequest(event, mockContext);
        Map<String, String> pageResponse =
                objectMapper.readValue(response.getBody(), new TypeReference<>() {});

        ArgumentCaptor<IpvSessionItem> sessionArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(mockIpvSessionService).updateIpvSession(sessionArgumentCaptor.capture());
        assertEquals(
                UserStates.CRI_ERROR.toString(), sessionArgumentCaptor.getValue().getUserState());

        assertEquals(200, response.getStatusCode());
        assertEquals(UserStates.PYI_TECHNICAL_ERROR_PAGE.value, pageResponse.get("page"));
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

        when(mockConfigurationService.getSsmParameter(BACKEND_SESSION_TIMEOUT)).thenReturn("7200");
        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);

        APIGatewayProxyResponseEvent response =
                processJourneyStepHandler.handleRequest(event, mockContext);
        Map<String, String> journeyResponse =
                objectMapper.readValue(response.getBody(), new TypeReference<>() {});

        assertEquals(200, response.getStatusCode());
        assertEquals("/journey/session/end", journeyResponse.get("journey"));
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
                processJourneyStepHandler.handleRequest(event, mockContext);
        Map<String, String> pageResponse =
                objectMapper.readValue(response.getBody(), new TypeReference<>() {});

        assertEquals(200, response.getStatusCode());
        assertEquals(UserStates.DEBUG_PAGE.value, pageResponse.get("page"));
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
                processJourneyStepHandler.handleRequest(event, mockContext);
        Map<String, String> pageResponse =
                objectMapper.readValue(response.getBody(), new TypeReference<>() {});

        ArgumentCaptor<IpvSessionItem> sessionArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(mockIpvSessionService).updateIpvSession(sessionArgumentCaptor.capture());
        assertEquals(
                UserStates.CRI_ERROR.toString(), sessionArgumentCaptor.getValue().getUserState());

        assertEquals(200, response.getStatusCode());
        assertEquals(UserStates.PYI_TECHNICAL_ERROR_PAGE.value, pageResponse.get("page"));
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
                processJourneyStepHandler.handleRequest(event, mockContext);
        Map<String, String> pageResponse =
                objectMapper.readValue(response.getBody(), new TypeReference<>() {});

        ArgumentCaptor<IpvSessionItem> sessionArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(mockIpvSessionService).updateIpvSession(sessionArgumentCaptor.capture());
        assertEquals(
                UserStates.PYI_NO_MATCH.toString(),
                sessionArgumentCaptor.getValue().getUserState());

        assertEquals(200, response.getStatusCode());
        assertEquals(UserStates.PYI_NO_MATCH.value, pageResponse.get("page"));
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

        when(mockConfigurationService.getSsmParameter(BACKEND_SESSION_TIMEOUT)).thenReturn("7200");
        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);

        APIGatewayProxyResponseEvent response =
                processJourneyStepHandler.handleRequest(event, mockContext);
        Map<String, String> journeyResponse =
                objectMapper.readValue(response.getBody(), new TypeReference<>() {});

        assertEquals(200, response.getStatusCode());
        assertEquals("/journey/session/end", journeyResponse.get("journey"));
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
                processJourneyStepHandler.handleRequest(event, mockContext);
        Map<String, String> pageResponse =
                objectMapper.readValue(response.getBody(), new TypeReference<>() {});

        ArgumentCaptor<IpvSessionItem> sessionArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(mockIpvSessionService).updateIpvSession(sessionArgumentCaptor.capture());
        assertEquals(
                UserStates.PYI_NO_MATCH.toString(),
                sessionArgumentCaptor.getValue().getUserState());

        assertEquals(200, response.getStatusCode());
        assertEquals(UserStates.PYI_NO_MATCH.value, pageResponse.get("page"));
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
                processJourneyStepHandler.handleRequest(event, mockContext);
        Map<String, String> pageResponse =
                objectMapper.readValue(response.getBody(), new TypeReference<>() {});

        ArgumentCaptor<IpvSessionItem> sessionArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(mockIpvSessionService).updateIpvSession(sessionArgumentCaptor.capture());
        assertEquals(
                UserStates.PYI_NO_MATCH.toString(),
                sessionArgumentCaptor.getValue().getUserState());

        assertEquals(200, response.getStatusCode());
        assertEquals(UserStates.PYI_NO_MATCH.value, pageResponse.get("page"));
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

        when(mockConfigurationService.getSsmParameter(BACKEND_SESSION_TIMEOUT)).thenReturn("7200");
        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);

        APIGatewayProxyResponseEvent response =
                processJourneyStepHandler.handleRequest(event, mockContext);
        Map<String, String> pageResponse =
                objectMapper.readValue(response.getBody(), new TypeReference<>() {});

        ArgumentCaptor<IpvSessionItem> sessionArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(mockIpvSessionService).updateIpvSession(sessionArgumentCaptor.capture());

        assertEquals(
                UserStates.PYI_KBV_FAIL.toString(),
                sessionArgumentCaptor.getValue().getUserState());

        assertEquals(200, response.getStatusCode());
        assertEquals(UserStates.PYI_KBV_FAIL.value, pageResponse.get("page"));
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
                processJourneyStepHandler.handleRequest(event, mockContext);
        Map<String, String> pageResponse =
                objectMapper.readValue(response.getBody(), new TypeReference<>() {});

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
        assertEquals(UserStates.PYI_TECHNICAL_ERROR_PAGE.value, pageResponse.get("page"));
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

        when(mockIpvSessionService.getIpvSession("1234")).thenReturn(ipvSessionItem);

        APIGatewayProxyResponseEvent response =
                processJourneyStepHandler.handleRequest(event, mockContext);
        Map<String, String> journeyResponse =
                objectMapper.readValue(response.getBody(), new TypeReference<>() {});

        assertEquals(200, response.getStatusCode());
        assertEquals("/journey/session/end", journeyResponse.get("journey"));
    }
}
