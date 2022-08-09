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
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.dto.ClientSessionDetailsDto;
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

    private static final String INITIAL_IPV_JOURNEY_STATE = "INITIAL_IPV_JOURNEY";
    private static final String IPV_IDENTITY_START_PAGE_STATE = "IPV_IDENTITY_START_PAGE";
    private static final String CRI_UK_PASSPORT_STATE = "CRI_UK_PASSPORT";
    private static final String CRI_ADDRESS_STATE = "CRI_ADDRESS";
    private static final String CRI_FRAUD_STATE = "CRI_FRAUD";
    private static final String CRI_KBV_STATE = "CRI_KBV";
    private static final String CRI_ERROR_STATE = "CRI_ERROR";
    private static final String EVALUATE_GPG45_SCORES = "EVALUATE_GPG45_SCORES";
    private static final String PRE_KBV_TRANSITION_PAGE_STATE = "PRE_KBV_TRANSITION_PAGE";
    private static final String IPV_SUCCESS_PAGE_STATE = "IPV_SUCCESS_PAGE";
    private static final String DEBUG_PAGE_STATE = "DEBUG_PAGE";
    private static final String PYI_NO_MATCH_STATE = "PYI_NO_MATCH";
    private static final String PYI_KBV_FAIL_STATE = "PYI_KBV_FAIL";
    private static final String CORE_SESSION_TIMEOUT_STATE = "CORE_SESSION_TIMEOUT";

    private static final String IPV_IDENTITY_START_PAGE = "page-ipv-identity-start";
    private static final String PYI_TECHNICAL_ERROR_PAGE = "pyi-technical";
    private static final String PYI_NO_MATCH_PAGE = "pyi-no-match";
    private static final String PYI_KBV_FAIL_PAGE = "pyi-kbv-fail";
    private static final String PRE_KBV_TRANSITION_PAGE = "page-pre-kbv-transition";
    private static final String IPV_SUCCESS_PAGE = "page-ipv-success";
    private static final String DEBUG_PAGE = "page-ipv-debug";
    public static final String JOURNEY_EVALUATE_GPG_45_SCORES = "/journey/evaluate-gpg45-scores";

    @Mock private Context mockContext;
    @Mock private IpvSessionService mockIpvSessionService;
    @Mock private ConfigurationService mockConfigurationService;

    private ProcessJourneyStepHandler processJourneyStepHandler;
    private final ObjectMapper objectMapper = new ObjectMapper();

    private ClientSessionDetailsDto clientSessionDetailsDto;

    @BeforeEach
    void setUp() throws Exception {
        StateMachine stateMachine = new StateMachine(new StateMachineInitializer("production"));
        processJourneyStepHandler =
                new ProcessJourneyStepHandler(
                        stateMachine, mockIpvSessionService, mockConfigurationService);
        clientSessionDetailsDto = new ClientSessionDetailsDto();
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
        ipvSessionItem.setUserState(INITIAL_IPV_JOURNEY_STATE);
        ipvSessionItem.setClientSessionDetails(clientSessionDetailsDto);

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
        ipvSessionItem.setClientSessionDetails(clientSessionDetailsDto);

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
        ipvSessionItem.setUserState(INITIAL_IPV_JOURNEY_STATE);
        ipvSessionItem.setClientSessionDetails(clientSessionDetailsDto);

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
                IPV_IDENTITY_START_PAGE_STATE, sessionArgumentCaptor.getValue().getUserState());

        assertEquals(200, response.getStatusCode());
        assertEquals(IPV_IDENTITY_START_PAGE, pageResponse.get("page"));
    }

    @Test
    void shouldReturnEvaluateGpg45ScoresWhenIpvIdentityStartPageState() throws IOException {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();

        Map<String, String> pathParameters = new HashMap<>();
        pathParameters.put(JOURNEY_STEP, NEXT);
        event.setPathParameters(pathParameters);

        event.setHeaders(Map.of("ipv-session-id", "1234"));

        IpvSessionItem ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setIpvSessionId(SecureTokenHelper.generate());
        ipvSessionItem.setCreationDateTime(Instant.now().toString());
        ipvSessionItem.setUserState(IPV_IDENTITY_START_PAGE_STATE);
        ipvSessionItem.setClientSessionDetails(clientSessionDetailsDto);

        when(mockConfigurationService.getSsmParameter(BACKEND_SESSION_TIMEOUT)).thenReturn("7200");
        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);

        APIGatewayProxyResponseEvent response =
                processJourneyStepHandler.handleRequest(event, mockContext);
        Map<String, String> criResponse =
                objectMapper.readValue(response.getBody(), new TypeReference<>() {});

        ArgumentCaptor<IpvSessionItem> sessionArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(mockIpvSessionService).updateIpvSession(sessionArgumentCaptor.capture());
        assertEquals(EVALUATE_GPG45_SCORES, sessionArgumentCaptor.getValue().getUserState());

        assertEquals(200, response.getStatusCode());
        assertEquals(JOURNEY_EVALUATE_GPG_45_SCORES, criResponse.get("journey"));
    }

    @Test
    void shouldReturnEvaluateGpg45ScoresWhenCriUkPassportState() throws IOException {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();

        Map<String, String> pathParameters = new HashMap<>();
        pathParameters.put(JOURNEY_STEP, NEXT);
        event.setPathParameters(pathParameters);

        event.setHeaders(Map.of("ipv-session-id", "1234"));

        IpvSessionItem ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setIpvSessionId(SecureTokenHelper.generate());
        ipvSessionItem.setCreationDateTime(Instant.now().toString());
        ipvSessionItem.setUserState(CRI_UK_PASSPORT_STATE);
        ipvSessionItem.setClientSessionDetails(clientSessionDetailsDto);

        when(mockConfigurationService.getSsmParameter(BACKEND_SESSION_TIMEOUT)).thenReturn("7200");
        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);

        APIGatewayProxyResponseEvent response =
                processJourneyStepHandler.handleRequest(event, mockContext);
        Map<String, String> criResponse =
                objectMapper.readValue(response.getBody(), new TypeReference<>() {});

        ArgumentCaptor<IpvSessionItem> sessionArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(mockIpvSessionService).updateIpvSession(sessionArgumentCaptor.capture());
        assertEquals(EVALUATE_GPG45_SCORES, sessionArgumentCaptor.getValue().getUserState());

        assertEquals(200, response.getStatusCode());
        assertEquals(JOURNEY_EVALUATE_GPG_45_SCORES, criResponse.get("journey"));
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
        ipvSessionItem.setUserState(CRI_UK_PASSPORT_STATE);
        ipvSessionItem.setClientSessionDetails(clientSessionDetailsDto);

        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);
        when(mockConfigurationService.getSsmParameter(BACKEND_SESSION_TIMEOUT)).thenReturn("7200");

        APIGatewayProxyResponseEvent response =
                processJourneyStepHandler.handleRequest(event, mockContext);
        Map<String, String> pageResponse =
                objectMapper.readValue(response.getBody(), new TypeReference<>() {});

        ArgumentCaptor<IpvSessionItem> sessionArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(mockIpvSessionService).updateIpvSession(sessionArgumentCaptor.capture());
        assertEquals(CRI_ERROR_STATE, sessionArgumentCaptor.getValue().getUserState());

        assertEquals(200, response.getStatusCode());
        assertEquals(PYI_TECHNICAL_ERROR_PAGE, pageResponse.get("page"));
    }

    @Test
    void shouldReturnEvaluateGpg45ScoresWhenCriAddressState() throws IOException {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();

        Map<String, String> pathParameters = new HashMap<>();
        pathParameters.put(JOURNEY_STEP, NEXT);
        event.setPathParameters(pathParameters);

        event.setHeaders(Map.of("ipv-session-id", "1234"));

        IpvSessionItem ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setIpvSessionId(SecureTokenHelper.generate());
        ipvSessionItem.setCreationDateTime(Instant.now().toString());
        ipvSessionItem.setUserState(CRI_ADDRESS_STATE);
        ipvSessionItem.setClientSessionDetails(clientSessionDetailsDto);

        when(mockConfigurationService.getSsmParameter(BACKEND_SESSION_TIMEOUT)).thenReturn("7200");
        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);
        when(mockConfigurationService.getSsmParameter(BACKEND_SESSION_TIMEOUT)).thenReturn("7200");

        when(mockConfigurationService.getSsmParameter(BACKEND_SESSION_TIMEOUT)).thenReturn("7200");
        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);

        APIGatewayProxyResponseEvent response =
                processJourneyStepHandler.handleRequest(event, mockContext);
        Map<String, String> criResponse =
                objectMapper.readValue(response.getBody(), new TypeReference<>() {});

        ArgumentCaptor<IpvSessionItem> sessionArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(mockIpvSessionService).updateIpvSession(sessionArgumentCaptor.capture());
        assertEquals(EVALUATE_GPG45_SCORES, sessionArgumentCaptor.getValue().getUserState());

        assertEquals(200, response.getStatusCode());
        assertEquals(JOURNEY_EVALUATE_GPG_45_SCORES, criResponse.get("journey"));
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
        ipvSessionItem.setUserState(CRI_ADDRESS_STATE);
        ipvSessionItem.setClientSessionDetails(clientSessionDetailsDto);

        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);
        when(mockConfigurationService.getSsmParameter(BACKEND_SESSION_TIMEOUT)).thenReturn("7200");

        APIGatewayProxyResponseEvent response =
                processJourneyStepHandler.handleRequest(event, mockContext);
        Map<String, String> pageResponse =
                objectMapper.readValue(response.getBody(), new TypeReference<>() {});

        ArgumentCaptor<IpvSessionItem> sessionArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(mockIpvSessionService).updateIpvSession(sessionArgumentCaptor.capture());
        assertEquals(CRI_ERROR_STATE, sessionArgumentCaptor.getValue().getUserState());

        assertEquals(200, response.getStatusCode());
        assertEquals(PYI_TECHNICAL_ERROR_PAGE, pageResponse.get("page"));
    }

    @Test
    void shouldReturnEvaluateGpg45ScoresWhenCriFraudState() throws IOException {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();

        Map<String, String> pathParameters = new HashMap<>();
        pathParameters.put(JOURNEY_STEP, NEXT);
        event.setPathParameters(pathParameters);

        event.setHeaders(Map.of("ipv-session-id", "1234"));

        IpvSessionItem ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setIpvSessionId(SecureTokenHelper.generate());
        ipvSessionItem.setCreationDateTime(Instant.now().toString());
        ipvSessionItem.setUserState(CRI_FRAUD_STATE);
        ipvSessionItem.setClientSessionDetails(clientSessionDetailsDto);

        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);
        when(mockConfigurationService.getSsmParameter(BACKEND_SESSION_TIMEOUT)).thenReturn("7200");

        APIGatewayProxyResponseEvent response =
                processJourneyStepHandler.handleRequest(event, mockContext);
        Map<String, String> pageResponse =
                objectMapper.readValue(response.getBody(), new TypeReference<>() {});

        ArgumentCaptor<IpvSessionItem> sessionArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(mockIpvSessionService).updateIpvSession(sessionArgumentCaptor.capture());
        assertEquals(EVALUATE_GPG45_SCORES, sessionArgumentCaptor.getValue().getUserState());

        assertEquals(200, response.getStatusCode());
        assertEquals(JOURNEY_EVALUATE_GPG_45_SCORES, pageResponse.get("journey"));
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
        ipvSessionItem.setUserState(PRE_KBV_TRANSITION_PAGE_STATE);
        ipvSessionItem.setClientSessionDetails(clientSessionDetailsDto);

        when(mockConfigurationService.getSsmParameter(BACKEND_SESSION_TIMEOUT)).thenReturn("7200");
        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);
        when(mockConfigurationService.getSsmParameter(BACKEND_SESSION_TIMEOUT)).thenReturn("7200");
        when(mockConfigurationService.getSsmParameter(BACKEND_SESSION_TIMEOUT)).thenReturn("7200");
        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);

        APIGatewayProxyResponseEvent response =
                processJourneyStepHandler.handleRequest(event, mockContext);
        Map<String, String> criResponse =
                objectMapper.readValue(response.getBody(), new TypeReference<>() {});

        ArgumentCaptor<IpvSessionItem> sessionArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(mockIpvSessionService).updateIpvSession(sessionArgumentCaptor.capture());
        assertEquals(CRI_KBV_STATE, sessionArgumentCaptor.getValue().getUserState());

        assertEquals(200, response.getStatusCode());
        assertEquals("/journey/cri/build-oauth-request/kbv", criResponse.get("journey"));
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
        ipvSessionItem.setUserState(CRI_FRAUD_STATE);
        ipvSessionItem.setClientSessionDetails(clientSessionDetailsDto);

        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);
        when(mockConfigurationService.getSsmParameter(BACKEND_SESSION_TIMEOUT)).thenReturn("7200");

        APIGatewayProxyResponseEvent response =
                processJourneyStepHandler.handleRequest(event, mockContext);
        Map<String, String> pageResponse =
                objectMapper.readValue(response.getBody(), new TypeReference<>() {});

        ArgumentCaptor<IpvSessionItem> sessionArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(mockIpvSessionService).updateIpvSession(sessionArgumentCaptor.capture());
        assertEquals(CRI_ERROR_STATE, sessionArgumentCaptor.getValue().getUserState());

        assertEquals(200, response.getStatusCode());
        assertEquals(PYI_TECHNICAL_ERROR_PAGE, pageResponse.get("page"));
    }

    @Test
    void shouldReturnEvaluateGpg45ScoresWhenCriKbvState() throws IOException {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();

        Map<String, String> pathParameters = new HashMap<>();
        pathParameters.put(JOURNEY_STEP, NEXT);
        event.setPathParameters(pathParameters);

        event.setHeaders(Map.of("ipv-session-id", "1234"));

        IpvSessionItem ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setIpvSessionId(SecureTokenHelper.generate());
        ipvSessionItem.setCreationDateTime(Instant.now().toString());
        ipvSessionItem.setUserState(CRI_KBV_STATE);
        ipvSessionItem.setClientSessionDetails(clientSessionDetailsDto);

        when(mockConfigurationService.getSsmParameter(BACKEND_SESSION_TIMEOUT)).thenReturn("7200");
        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);
        when(mockConfigurationService.getSsmParameter(BACKEND_SESSION_TIMEOUT)).thenReturn("7200");
        when(mockConfigurationService.getSsmParameter(BACKEND_SESSION_TIMEOUT)).thenReturn("7200");
        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);

        APIGatewayProxyResponseEvent response =
                processJourneyStepHandler.handleRequest(event, mockContext);
        Map<String, String> pageResponse =
                objectMapper.readValue(response.getBody(), new TypeReference<>() {});

        ArgumentCaptor<IpvSessionItem> sessionArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(mockIpvSessionService).updateIpvSession(sessionArgumentCaptor.capture());

        assertEquals(EVALUATE_GPG45_SCORES, sessionArgumentCaptor.getValue().getUserState());

        assertEquals(200, response.getStatusCode());
        assertEquals(JOURNEY_EVALUATE_GPG_45_SCORES, pageResponse.get("journey"));
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
        ipvSessionItem.setUserState(CRI_KBV_STATE);
        ipvSessionItem.setClientSessionDetails(clientSessionDetailsDto);

        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);
        when(mockConfigurationService.getSsmParameter(BACKEND_SESSION_TIMEOUT)).thenReturn("7200");

        APIGatewayProxyResponseEvent response =
                processJourneyStepHandler.handleRequest(event, mockContext);
        Map<String, String> pageResponse =
                objectMapper.readValue(response.getBody(), new TypeReference<>() {});

        ArgumentCaptor<IpvSessionItem> sessionArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(mockIpvSessionService).updateIpvSession(sessionArgumentCaptor.capture());
        assertEquals(CRI_ERROR_STATE, sessionArgumentCaptor.getValue().getUserState());

        assertEquals(200, response.getStatusCode());
        assertEquals(PYI_TECHNICAL_ERROR_PAGE, pageResponse.get("page"));
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
        ipvSessionItem.setUserState(IPV_SUCCESS_PAGE_STATE);
        ipvSessionItem.setClientSessionDetails(clientSessionDetailsDto);

        when(mockConfigurationService.getSsmParameter(BACKEND_SESSION_TIMEOUT)).thenReturn("7200");
        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);
        when(mockConfigurationService.getSsmParameter(BACKEND_SESSION_TIMEOUT)).thenReturn("7200");
        when(mockConfigurationService.getSsmParameter(BACKEND_SESSION_TIMEOUT)).thenReturn("7200");
        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);

        APIGatewayProxyResponseEvent response =
                processJourneyStepHandler.handleRequest(event, mockContext);
        Map<String, String> journeyResponse =
                objectMapper.readValue(response.getBody(), new TypeReference<>() {});

        assertEquals(200, response.getStatusCode());
        assertEquals("/journey/build-client-oauth-response", journeyResponse.get("journey"));
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
        ipvSessionItem.setUserState(DEBUG_PAGE_STATE);
        ipvSessionItem.setClientSessionDetails(clientSessionDetailsDto);

        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);
        when(mockConfigurationService.getSsmParameter(BACKEND_SESSION_TIMEOUT)).thenReturn("7200");

        APIGatewayProxyResponseEvent response =
                processJourneyStepHandler.handleRequest(event, mockContext);
        Map<String, String> pageResponse =
                objectMapper.readValue(response.getBody(), new TypeReference<>() {});

        assertEquals(200, response.getStatusCode());
        assertEquals(DEBUG_PAGE, pageResponse.get("page"));
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
        ipvSessionItem.setUserState(DEBUG_PAGE_STATE);
        ipvSessionItem.setClientSessionDetails(clientSessionDetailsDto);

        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);
        when(mockConfigurationService.getSsmParameter(BACKEND_SESSION_TIMEOUT)).thenReturn("7200");

        APIGatewayProxyResponseEvent response =
                processJourneyStepHandler.handleRequest(event, mockContext);
        Map<String, String> pageResponse =
                objectMapper.readValue(response.getBody(), new TypeReference<>() {});

        ArgumentCaptor<IpvSessionItem> sessionArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(mockIpvSessionService).updateIpvSession(sessionArgumentCaptor.capture());
        assertEquals(CRI_ERROR_STATE, sessionArgumentCaptor.getValue().getUserState());

        assertEquals(200, response.getStatusCode());
        assertEquals(PYI_TECHNICAL_ERROR_PAGE, pageResponse.get("page"));
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
        ipvSessionItem.setUserState(DEBUG_PAGE_STATE);
        ipvSessionItem.setClientSessionDetails(clientSessionDetailsDto);

        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);
        when(mockConfigurationService.getSsmParameter(BACKEND_SESSION_TIMEOUT)).thenReturn("7200");

        APIGatewayProxyResponseEvent response =
                processJourneyStepHandler.handleRequest(event, mockContext);
        Map<String, String> pageResponse =
                objectMapper.readValue(response.getBody(), new TypeReference<>() {});

        ArgumentCaptor<IpvSessionItem> sessionArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(mockIpvSessionService).updateIpvSession(sessionArgumentCaptor.capture());
        assertEquals(PYI_NO_MATCH_STATE, sessionArgumentCaptor.getValue().getUserState());

        assertEquals(200, response.getStatusCode());
        assertEquals(PYI_NO_MATCH_PAGE, pageResponse.get("page"));
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
        ipvSessionItem.setUserState(CRI_ERROR_STATE);
        ipvSessionItem.setClientSessionDetails(clientSessionDetailsDto);

        when(mockConfigurationService.getSsmParameter(BACKEND_SESSION_TIMEOUT)).thenReturn("7200");
        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);
        when(mockConfigurationService.getSsmParameter(BACKEND_SESSION_TIMEOUT)).thenReturn("7200");

        when(mockConfigurationService.getSsmParameter(BACKEND_SESSION_TIMEOUT)).thenReturn("7200");
        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);

        APIGatewayProxyResponseEvent response =
                processJourneyStepHandler.handleRequest(event, mockContext);
        Map<String, String> journeyResponse =
                objectMapper.readValue(response.getBody(), new TypeReference<>() {});

        assertEquals(200, response.getStatusCode());
        assertEquals("/journey/build-client-oauth-response", journeyResponse.get("journey"));
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
        ipvSessionItem.setUserState(CRI_UK_PASSPORT_STATE);
        ipvSessionItem.setClientSessionDetails(clientSessionDetailsDto);

        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);
        when(mockConfigurationService.getSsmParameter(BACKEND_SESSION_TIMEOUT)).thenReturn("7200");

        APIGatewayProxyResponseEvent response =
                processJourneyStepHandler.handleRequest(event, mockContext);
        Map<String, String> pageResponse =
                objectMapper.readValue(response.getBody(), new TypeReference<>() {});

        ArgumentCaptor<IpvSessionItem> sessionArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(mockIpvSessionService).updateIpvSession(sessionArgumentCaptor.capture());
        assertEquals(PYI_NO_MATCH_STATE, sessionArgumentCaptor.getValue().getUserState());

        assertEquals(200, response.getStatusCode());
        assertEquals(PYI_NO_MATCH_PAGE, pageResponse.get("page"));
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
        ipvSessionItem.setUserState(CRI_FRAUD_STATE);
        ipvSessionItem.setClientSessionDetails(clientSessionDetailsDto);

        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);
        when(mockConfigurationService.getSsmParameter(BACKEND_SESSION_TIMEOUT)).thenReturn("7200");

        APIGatewayProxyResponseEvent response =
                processJourneyStepHandler.handleRequest(event, mockContext);
        Map<String, String> pageResponse =
                objectMapper.readValue(response.getBody(), new TypeReference<>() {});

        ArgumentCaptor<IpvSessionItem> sessionArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(mockIpvSessionService).updateIpvSession(sessionArgumentCaptor.capture());
        assertEquals(PYI_NO_MATCH_STATE, sessionArgumentCaptor.getValue().getUserState());

        assertEquals(200, response.getStatusCode());
        assertEquals(PYI_NO_MATCH_PAGE, pageResponse.get("page"));
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
        ipvSessionItem.setUserState(CRI_KBV_STATE);
        ipvSessionItem.setClientSessionDetails(clientSessionDetailsDto);

        when(mockConfigurationService.getSsmParameter(BACKEND_SESSION_TIMEOUT)).thenReturn("7200");
        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);
        when(mockConfigurationService.getSsmParameter(BACKEND_SESSION_TIMEOUT)).thenReturn("7200");
        when(mockConfigurationService.getSsmParameter(BACKEND_SESSION_TIMEOUT)).thenReturn("7200");
        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);

        APIGatewayProxyResponseEvent response =
                processJourneyStepHandler.handleRequest(event, mockContext);
        Map<String, String> pageResponse =
                objectMapper.readValue(response.getBody(), new TypeReference<>() {});

        ArgumentCaptor<IpvSessionItem> sessionArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(mockIpvSessionService).updateIpvSession(sessionArgumentCaptor.capture());

        assertEquals(PYI_KBV_FAIL_STATE, sessionArgumentCaptor.getValue().getUserState());

        assertEquals(200, response.getStatusCode());
        assertEquals(PYI_KBV_FAIL_PAGE, pageResponse.get("page"));
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
        ipvSessionItem.setUserState(CRI_UK_PASSPORT_STATE);
        ipvSessionItem.setClientSessionDetails(clientSessionDetailsDto);

        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);
        when(mockConfigurationService.getSsmParameter(BACKEND_SESSION_TIMEOUT)).thenReturn("99");
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
        assertEquals(CORE_SESSION_TIMEOUT_STATE, capturedIpvSessionItem.getUserState());
        assertEquals(OAuth2Error.ACCESS_DENIED.getCode(), capturedIpvSessionItem.getErrorCode());
        assertEquals(
                OAuth2Error.ACCESS_DENIED.getDescription(),
                capturedIpvSessionItem.getErrorDescription());

        assertEquals(200, response.getStatusCode());
        assertEquals(PYI_TECHNICAL_ERROR_PAGE, pageResponse.get("page"));
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
        ipvSessionItem.setUserState(CORE_SESSION_TIMEOUT_STATE);
        ipvSessionItem.setClientSessionDetails(clientSessionDetailsDto);

        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);
        when(mockIpvSessionService.getIpvSession("1234")).thenReturn(ipvSessionItem);

        APIGatewayProxyResponseEvent response =
                processJourneyStepHandler.handleRequest(event, mockContext);
        Map<String, String> journeyResponse =
                objectMapper.readValue(response.getBody(), new TypeReference<>() {});

        assertEquals(200, response.getStatusCode());
        assertEquals("/journey/build-client-oauth-response", journeyResponse.get("journey"));
    }
}
