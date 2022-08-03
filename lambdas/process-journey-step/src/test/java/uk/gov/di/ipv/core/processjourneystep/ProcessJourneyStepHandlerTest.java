package uk.gov.di.ipv.core.processjourneystep;

import com.amazonaws.services.lambda.runtime.Context;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.domain.ApiGatewayTemplateMappingInput;
import uk.gov.di.ipv.core.library.domain.ApiGatewayTemplateMappingOutput;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.helpers.SecureTokenHelper;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.ConfigurationService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.processjourneystep.statemachine.StateMachine;
import uk.gov.di.ipv.core.processjourneystep.statemachine.StateMachineInitializer;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.time.Instant;
import java.util.Collections;
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
    private static final String PRE_KBV_TRANSITION_PAGE_STATE = "PRE_KBV_TRANSITION_PAGE";
    private static final String IPV_SUCCESS_PAGE_STATE = "IPV_SUCCESS_PAGE";
    private static final String DEBUG_PAGE_STATE = "DEBUG_PAGE";
    private static final String PYI_NO_MATCH_STATE = "PYI_NO_MATCH";
    private static final String PYI_KBV_FAIL_STATE = "PYI_KBV_FAIL";
    private static final String CORE_SESSION_TIMEOUT_STATE = "CORE_SESSION_TIMEOUT";
    private static final String END_STATE = "END";

    private static final String IPV_IDENTITY_START_PAGE = "page-ipv-identity-start";
    private static final String PYI_TECHNICAL_ERROR_PAGE = "pyi-technical";
    private static final String PYI_NO_MATCH_PAGE = "pyi-no-match";
    private static final String PYI_KBV_FAIL_PAGE = "pyi-kbv-fail";
    private static final String PRE_KBV_TRANSITION_PAGE = "page-pre-kbv-transition";
    private static final String IPV_SUCCESS_PAGE = "page-ipv-success";
    private static final String DEBUG_PAGE = "page-ipv-debug";

    @Mock private Context mockContext;
    @Mock private IpvSessionService mockIpvSessionService;
    @Mock private ConfigurationService mockConfigurationService;

    private ProcessJourneyStepHandler processJourneyStepHandler;
    private final ObjectMapper objectMapper = new ObjectMapper();

    @BeforeEach
    void setUp() throws Exception {
        StateMachine stateMachine = new StateMachine(new StateMachineInitializer("production"));
        processJourneyStepHandler =
                new ProcessJourneyStepHandler(
                        stateMachine, mockIpvSessionService, mockConfigurationService);
    }

    @Test
    void shouldReturn400OnMissingParams() throws IOException {
        var input =
                new ApiGatewayTemplateMappingInput(
                        Map.of("input", "body"),
                        Map.of("ipv-session-id", "1234"),
                        Collections.emptyMap(),
                        Collections.emptyMap());
        InputStream inputStream = new ByteArrayInputStream(objectMapper.writeValueAsBytes(input));
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

        processJourneyStepHandler.handleRequest(inputStream, outputStream, mockContext);

        ApiGatewayTemplateMappingOutput lambdaOutput =
                objectMapper.readValue(
                        outputStream.toByteArray(), ApiGatewayTemplateMappingOutput.class);
        Map<String, Object> outputBody =
                objectMapper.readValue(lambdaOutput.getBody(), new TypeReference<>() {});

        assertEquals(400, lambdaOutput.getStatusCode());
        assertEquals(
                ErrorResponse.MISSING_JOURNEY_STEP_URL_PATH_PARAM.getCode(),
                outputBody.get("code"));
        assertEquals(
                ErrorResponse.MISSING_JOURNEY_STEP_URL_PATH_PARAM.getMessage(),
                outputBody.get("message"));
    }

    @Test
    void shouldReturn400OnMissingJourneyStepParam() throws IOException {
        var input =
                new ApiGatewayTemplateMappingInput(
                        Map.of("input", "body"),
                        Map.of("ipv-session-id", "1234"),
                        Map.of("InvalidStep", "any"),
                        Collections.emptyMap());
        InputStream inputStream = new ByteArrayInputStream(objectMapper.writeValueAsBytes(input));
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

        processJourneyStepHandler.handleRequest(inputStream, outputStream, mockContext);

        ApiGatewayTemplateMappingOutput lambdaOutput =
                objectMapper.readValue(
                        outputStream.toByteArray(), ApiGatewayTemplateMappingOutput.class);
        Map<String, Object> outputBody =
                objectMapper.readValue(lambdaOutput.getBody(), new TypeReference<>() {});

        assertEquals(400, lambdaOutput.getStatusCode());
        assertEquals(
                ErrorResponse.MISSING_JOURNEY_STEP_URL_PATH_PARAM.getCode(),
                outputBody.get("code"));
        assertEquals(
                ErrorResponse.MISSING_JOURNEY_STEP_URL_PATH_PARAM.getMessage(),
                outputBody.get("message"));
    }

    @Test
    void shouldReturn400OnMissingIpvSessionIdHeader() throws IOException {
        var input =
                new ApiGatewayTemplateMappingInput(
                        Map.of("input", "body"),
                        Collections.emptyMap(),
                        Map.of(JOURNEY_STEP, NEXT),
                        Collections.emptyMap());
        InputStream inputStream = new ByteArrayInputStream(objectMapper.writeValueAsBytes(input));
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

        processJourneyStepHandler.handleRequest(inputStream, outputStream, mockContext);

        ApiGatewayTemplateMappingOutput lambdaOutput =
                objectMapper.readValue(
                        outputStream.toByteArray(), ApiGatewayTemplateMappingOutput.class);
        Map<String, Object> outputBody =
                objectMapper.readValue(lambdaOutput.getBody(), new TypeReference<>() {});

        assertEquals(400, lambdaOutput.getStatusCode());
        assertEquals(ErrorResponse.MISSING_IPV_SESSION_ID.getCode(), outputBody.get("error"));
        assertEquals(
                ErrorResponse.MISSING_IPV_SESSION_ID.getMessage(),
                outputBody.get("error_description"));
    }

    @Test
    void shouldReturn400WhenInvalidSessionIdProvided() throws IOException {
        var input =
                new ApiGatewayTemplateMappingInput(
                        Map.of("input", "body"),
                        Map.of("ipv-session-id", "1234"),
                        Map.of(JOURNEY_STEP, NEXT),
                        Collections.emptyMap());
        InputStream inputStream = new ByteArrayInputStream(objectMapper.writeValueAsBytes(input));
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

        when(mockIpvSessionService.getIpvSession("1234")).thenReturn(null);

        processJourneyStepHandler.handleRequest(inputStream, outputStream, mockContext);

        ApiGatewayTemplateMappingOutput lambdaOutput =
                objectMapper.readValue(
                        outputStream.toByteArray(), ApiGatewayTemplateMappingOutput.class);
        Map<String, Object> outputBody =
                objectMapper.readValue(lambdaOutput.getBody(), new TypeReference<>() {});

        assertEquals(400, lambdaOutput.getStatusCode());
        assertEquals(ErrorResponse.INVALID_SESSION_ID.getCode(), outputBody.get("code"));
        assertEquals(ErrorResponse.INVALID_SESSION_ID.getMessage(), outputBody.get("message"));
    }

    @Test
    void shouldReturn500WhenUnknownJourneyEngineStepProvided() throws IOException {
        var input =
                new ApiGatewayTemplateMappingInput(
                        Map.of("input", "body"),
                        Map.of("ipv-session-id", "1234"),
                        Map.of(JOURNEY_STEP, INVALID_STEP),
                        Collections.emptyMap());
        InputStream inputStream = new ByteArrayInputStream(objectMapper.writeValueAsBytes(input));
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

        IpvSessionItem ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setIpvSessionId(SecureTokenHelper.generate());
        ipvSessionItem.setCreationDateTime(Instant.now().toString());
        ipvSessionItem.setUserState(INITIAL_IPV_JOURNEY_STATE);
        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);
        when(mockConfigurationService.getSsmParameter(BACKEND_SESSION_TIMEOUT)).thenReturn("7200");

        processJourneyStepHandler.handleRequest(inputStream, outputStream, mockContext);

        ApiGatewayTemplateMappingOutput lambdaOutput =
                objectMapper.readValue(
                        outputStream.toByteArray(), ApiGatewayTemplateMappingOutput.class);
        Map<String, Object> outputBody =
                objectMapper.readValue(lambdaOutput.getBody(), new TypeReference<>() {});

        assertEquals(500, lambdaOutput.getStatusCode());
        assertEquals(ErrorResponse.FAILED_JOURNEY_ENGINE_STEP.getCode(), outputBody.get("code"));
        assertEquals(
                ErrorResponse.FAILED_JOURNEY_ENGINE_STEP.getMessage(), outputBody.get("message"));
    }

    @Test
    void shouldReturn500WhenUserIsInUnknownState() throws IOException {
        var input =
                new ApiGatewayTemplateMappingInput(
                        Map.of("input", "body"),
                        Map.of("ipv-session-id", "1234"),
                        Map.of(JOURNEY_STEP, NEXT),
                        Collections.emptyMap());
        InputStream inputStream = new ByteArrayInputStream(objectMapper.writeValueAsBytes(input));
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

        IpvSessionItem ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setIpvSessionId(SecureTokenHelper.generate());
        ipvSessionItem.setCreationDateTime(Instant.now().toString());
        ipvSessionItem.setUserState("INVALID-STATE");
        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);
        when(mockConfigurationService.getSsmParameter(BACKEND_SESSION_TIMEOUT)).thenReturn("7200");

        processJourneyStepHandler.handleRequest(inputStream, outputStream, mockContext);

        ApiGatewayTemplateMappingOutput lambdaOutput =
                objectMapper.readValue(
                        outputStream.toByteArray(), ApiGatewayTemplateMappingOutput.class);
        Map<String, Object> outputBody =
                objectMapper.readValue(lambdaOutput.getBody(), new TypeReference<>() {});

        assertEquals(500, lambdaOutput.getStatusCode());
        assertEquals(ErrorResponse.FAILED_JOURNEY_ENGINE_STEP.getCode(), outputBody.get("code"));
        assertEquals(
                ErrorResponse.FAILED_JOURNEY_ENGINE_STEP.getMessage(), outputBody.get("message"));
    }

    @Test
    void shouldReturnIdentityStartPageResponseWhenRequired() throws IOException {
        var input =
                new ApiGatewayTemplateMappingInput(
                        Map.of("input", "body"),
                        Map.of("ipv-session-id", "1234"),
                        Map.of(JOURNEY_STEP, NEXT),
                        Collections.emptyMap());
        InputStream inputStream = new ByteArrayInputStream(objectMapper.writeValueAsBytes(input));
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

        IpvSessionItem ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setIpvSessionId(SecureTokenHelper.generate());
        ipvSessionItem.setCreationDateTime(Instant.now().toString());
        ipvSessionItem.setUserState(INITIAL_IPV_JOURNEY_STATE);

        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);
        when(mockConfigurationService.getSsmParameter(BACKEND_SESSION_TIMEOUT)).thenReturn("7200");

        processJourneyStepHandler.handleRequest(inputStream, outputStream, mockContext);

        ApiGatewayTemplateMappingOutput lambdaOutput =
                objectMapper.readValue(
                        outputStream.toByteArray(), ApiGatewayTemplateMappingOutput.class);
        Map<String, Object> outputBody =
                objectMapper.readValue(lambdaOutput.getBody(), new TypeReference<>() {});

        assertEquals(200, lambdaOutput.getStatusCode());
        assertEquals(IPV_IDENTITY_START_PAGE, outputBody.get("page"));

        ArgumentCaptor<IpvSessionItem> sessionArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(mockIpvSessionService).updateIpvSession(sessionArgumentCaptor.capture());
        assertEquals(
                IPV_IDENTITY_START_PAGE_STATE, sessionArgumentCaptor.getValue().getUserState());
    }

    @Test
    void shouldReturnCriUkPassportJourneyResponseWhenRequired() throws IOException {
        var input =
                new ApiGatewayTemplateMappingInput(
                        Map.of("input", "body"),
                        Map.of("ipv-session-id", "1234"),
                        Map.of(JOURNEY_STEP, NEXT),
                        Collections.emptyMap());
        InputStream inputStream = new ByteArrayInputStream(objectMapper.writeValueAsBytes(input));
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

        IpvSessionItem ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setIpvSessionId(SecureTokenHelper.generate());
        ipvSessionItem.setCreationDateTime(Instant.now().toString());
        ipvSessionItem.setUserState(IPV_IDENTITY_START_PAGE_STATE);
        when(mockConfigurationService.getSsmParameter(BACKEND_SESSION_TIMEOUT)).thenReturn("7200");
        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);

        processJourneyStepHandler.handleRequest(inputStream, outputStream, mockContext);

        ApiGatewayTemplateMappingOutput lambdaOutput =
                objectMapper.readValue(
                        outputStream.toByteArray(), ApiGatewayTemplateMappingOutput.class);
        Map<String, Object> outputBody =
                objectMapper.readValue(lambdaOutput.getBody(), new TypeReference<>() {});

        ArgumentCaptor<IpvSessionItem> sessionArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(mockIpvSessionService).updateIpvSession(sessionArgumentCaptor.capture());
        assertEquals(CRI_UK_PASSPORT_STATE, sessionArgumentCaptor.getValue().getUserState());

        assertEquals(200, lambdaOutput.getStatusCode());
        assertEquals("/journey/cri/build-oauth-request/ukPassport", outputBody.get("journey"));
    }

    @Test
    void shouldReturnCriAddressJourneyResponseWhenRequired() throws IOException {
        var input =
                new ApiGatewayTemplateMappingInput(
                        Map.of("input", "body"),
                        Map.of("ipv-session-id", "1234"),
                        Map.of(JOURNEY_STEP, NEXT),
                        Collections.emptyMap());
        InputStream inputStream = new ByteArrayInputStream(objectMapper.writeValueAsBytes(input));
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

        IpvSessionItem ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setIpvSessionId(SecureTokenHelper.generate());
        ipvSessionItem.setCreationDateTime(Instant.now().toString());
        ipvSessionItem.setUserState(CRI_UK_PASSPORT_STATE);
        when(mockConfigurationService.getSsmParameter(BACKEND_SESSION_TIMEOUT)).thenReturn("7200");
        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);

        processJourneyStepHandler.handleRequest(inputStream, outputStream, mockContext);

        ApiGatewayTemplateMappingOutput lambdaOutput =
                objectMapper.readValue(
                        outputStream.toByteArray(), ApiGatewayTemplateMappingOutput.class);
        Map<String, Object> outputBody =
                objectMapper.readValue(lambdaOutput.getBody(), new TypeReference<>() {});

        ArgumentCaptor<IpvSessionItem> sessionArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(mockIpvSessionService).updateIpvSession(sessionArgumentCaptor.capture());
        assertEquals(CRI_ADDRESS_STATE, sessionArgumentCaptor.getValue().getUserState());

        assertEquals(200, lambdaOutput.getStatusCode());
        assertEquals("/journey/cri/build-oauth-request/address", outputBody.get("journey"));
    }

    @Test
    void shouldReturnCriErrorPageResponseIfPassportCriFails() throws IOException {
        var input =
                new ApiGatewayTemplateMappingInput(
                        Map.of("input", "body"),
                        Map.of("ipv-session-id", "1234"),
                        Map.of(JOURNEY_STEP, ERROR),
                        Collections.emptyMap());
        InputStream inputStream = new ByteArrayInputStream(objectMapper.writeValueAsBytes(input));
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

        IpvSessionItem ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setIpvSessionId(SecureTokenHelper.generate());
        ipvSessionItem.setCreationDateTime(Instant.now().toString());
        ipvSessionItem.setUserState(CRI_UK_PASSPORT_STATE);
        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);
        when(mockConfigurationService.getSsmParameter(BACKEND_SESSION_TIMEOUT)).thenReturn("7200");

        processJourneyStepHandler.handleRequest(inputStream, outputStream, mockContext);

        ApiGatewayTemplateMappingOutput lambdaOutput =
                objectMapper.readValue(
                        outputStream.toByteArray(), ApiGatewayTemplateMappingOutput.class);
        Map<String, Object> outputBody =
                objectMapper.readValue(lambdaOutput.getBody(), new TypeReference<>() {});

        ArgumentCaptor<IpvSessionItem> sessionArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(mockIpvSessionService).updateIpvSession(sessionArgumentCaptor.capture());
        assertEquals(CRI_ERROR_STATE, sessionArgumentCaptor.getValue().getUserState());

        assertEquals(200, lambdaOutput.getStatusCode());
        assertEquals(PYI_TECHNICAL_ERROR_PAGE, outputBody.get("page"));
    }

    @Test
    void shouldReturnCriFraudJourneyResponseWhenRequired() throws IOException {
        var input =
                new ApiGatewayTemplateMappingInput(
                        Map.of("input", "body"),
                        Map.of("ipv-session-id", "1234"),
                        Map.of(JOURNEY_STEP, NEXT),
                        Collections.emptyMap());
        InputStream inputStream = new ByteArrayInputStream(objectMapper.writeValueAsBytes(input));
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

        IpvSessionItem ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setIpvSessionId(SecureTokenHelper.generate());
        ipvSessionItem.setCreationDateTime(Instant.now().toString());
        ipvSessionItem.setUserState(CRI_ADDRESS_STATE);
        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);
        when(mockConfigurationService.getSsmParameter(BACKEND_SESSION_TIMEOUT)).thenReturn("7200");

        processJourneyStepHandler.handleRequest(inputStream, outputStream, mockContext);

        ApiGatewayTemplateMappingOutput lambdaOutput =
                objectMapper.readValue(
                        outputStream.toByteArray(), ApiGatewayTemplateMappingOutput.class);
        Map<String, Object> outputBody =
                objectMapper.readValue(lambdaOutput.getBody(), new TypeReference<>() {});

        ArgumentCaptor<IpvSessionItem> sessionArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(mockIpvSessionService).updateIpvSession(sessionArgumentCaptor.capture());
        assertEquals(CRI_FRAUD_STATE, sessionArgumentCaptor.getValue().getUserState());

        assertEquals(200, lambdaOutput.getStatusCode());
        assertEquals("/journey/cri/build-oauth-request/fraud", outputBody.get("journey"));
    }

    @Test
    void shouldReturnCriErrorPageResponseIfAddressCriFails() throws IOException {
        var input =
                new ApiGatewayTemplateMappingInput(
                        Map.of("input", "body"),
                        Map.of("ipv-session-id", "1234"),
                        Map.of(JOURNEY_STEP, ERROR),
                        Collections.emptyMap());
        InputStream inputStream = new ByteArrayInputStream(objectMapper.writeValueAsBytes(input));
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

        IpvSessionItem ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setIpvSessionId(SecureTokenHelper.generate());
        ipvSessionItem.setCreationDateTime(Instant.now().toString());
        ipvSessionItem.setUserState(CRI_ADDRESS_STATE);
        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);
        when(mockConfigurationService.getSsmParameter(BACKEND_SESSION_TIMEOUT)).thenReturn("7200");

        processJourneyStepHandler.handleRequest(inputStream, outputStream, mockContext);

        ApiGatewayTemplateMappingOutput lambdaOutput =
                objectMapper.readValue(
                        outputStream.toByteArray(), ApiGatewayTemplateMappingOutput.class);
        Map<String, Object> outputBody =
                objectMapper.readValue(lambdaOutput.getBody(), new TypeReference<>() {});

        ArgumentCaptor<IpvSessionItem> sessionArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(mockIpvSessionService).updateIpvSession(sessionArgumentCaptor.capture());
        assertEquals(CRI_ERROR_STATE, sessionArgumentCaptor.getValue().getUserState());

        assertEquals(200, lambdaOutput.getStatusCode());
        assertEquals(PYI_TECHNICAL_ERROR_PAGE, outputBody.get("page"));
    }

    @Test
    void shouldReturnPreKbvTransitionPageResponseWhenRequired() throws IOException {
        var input =
                new ApiGatewayTemplateMappingInput(
                        Map.of("input", "body"),
                        Map.of("ipv-session-id", "1234"),
                        Map.of(JOURNEY_STEP, NEXT),
                        Collections.emptyMap());
        InputStream inputStream = new ByteArrayInputStream(objectMapper.writeValueAsBytes(input));
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

        IpvSessionItem ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setIpvSessionId(SecureTokenHelper.generate());
        ipvSessionItem.setCreationDateTime(Instant.now().toString());
        ipvSessionItem.setUserState(CRI_FRAUD_STATE);
        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);
        when(mockConfigurationService.getSsmParameter(BACKEND_SESSION_TIMEOUT)).thenReturn("7200");

        processJourneyStepHandler.handleRequest(inputStream, outputStream, mockContext);

        ApiGatewayTemplateMappingOutput lambdaOutput =
                objectMapper.readValue(
                        outputStream.toByteArray(), ApiGatewayTemplateMappingOutput.class);
        Map<String, Object> outputBody =
                objectMapper.readValue(lambdaOutput.getBody(), new TypeReference<>() {});

        ArgumentCaptor<IpvSessionItem> sessionArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(mockIpvSessionService).updateIpvSession(sessionArgumentCaptor.capture());
        assertEquals(
                PRE_KBV_TRANSITION_PAGE_STATE, sessionArgumentCaptor.getValue().getUserState());

        assertEquals(200, lambdaOutput.getStatusCode());
        assertEquals(PRE_KBV_TRANSITION_PAGE, outputBody.get("page"));
    }

    @Test
    void shouldReturnCriKbvJourneyResponseWhenRequired() throws IOException {
        var input =
                new ApiGatewayTemplateMappingInput(
                        Map.of("input", "body"),
                        Map.of("ipv-session-id", "1234"),
                        Map.of(JOURNEY_STEP, NEXT),
                        Collections.emptyMap());
        InputStream inputStream = new ByteArrayInputStream(objectMapper.writeValueAsBytes(input));
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

        IpvSessionItem ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setIpvSessionId(SecureTokenHelper.generate());
        ipvSessionItem.setCreationDateTime(Instant.now().toString());
        ipvSessionItem.setUserState(PRE_KBV_TRANSITION_PAGE_STATE);
        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);
        when(mockConfigurationService.getSsmParameter(BACKEND_SESSION_TIMEOUT)).thenReturn("7200");

        processJourneyStepHandler.handleRequest(inputStream, outputStream, mockContext);

        ApiGatewayTemplateMappingOutput lambdaOutput =
                objectMapper.readValue(
                        outputStream.toByteArray(), ApiGatewayTemplateMappingOutput.class);
        Map<String, Object> outputBody =
                objectMapper.readValue(lambdaOutput.getBody(), new TypeReference<>() {});

        ArgumentCaptor<IpvSessionItem> sessionArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(mockIpvSessionService).updateIpvSession(sessionArgumentCaptor.capture());
        assertEquals(CRI_KBV_STATE, sessionArgumentCaptor.getValue().getUserState());

        assertEquals(200, lambdaOutput.getStatusCode());
        assertEquals("/journey/cri/build-oauth-request/kbv", outputBody.get("journey"));
    }

    @Test
    void shouldReturnCriErrorPageResponseIfFraudCriFails() throws IOException {
        var input =
                new ApiGatewayTemplateMappingInput(
                        Map.of("input", "body"),
                        Map.of("ipv-session-id", "1234"),
                        Map.of(JOURNEY_STEP, ERROR),
                        Collections.emptyMap());
        InputStream inputStream = new ByteArrayInputStream(objectMapper.writeValueAsBytes(input));
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

        IpvSessionItem ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setIpvSessionId(SecureTokenHelper.generate());
        ipvSessionItem.setCreationDateTime(Instant.now().toString());
        ipvSessionItem.setUserState(CRI_FRAUD_STATE);
        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);
        when(mockConfigurationService.getSsmParameter(BACKEND_SESSION_TIMEOUT)).thenReturn("7200");

        processJourneyStepHandler.handleRequest(inputStream, outputStream, mockContext);

        ApiGatewayTemplateMappingOutput lambdaOutput =
                objectMapper.readValue(
                        outputStream.toByteArray(), ApiGatewayTemplateMappingOutput.class);
        Map<String, Object> outputBody =
                objectMapper.readValue(lambdaOutput.getBody(), new TypeReference<>() {});

        ArgumentCaptor<IpvSessionItem> sessionArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(mockIpvSessionService).updateIpvSession(sessionArgumentCaptor.capture());
        assertEquals(CRI_ERROR_STATE, sessionArgumentCaptor.getValue().getUserState());

        assertEquals(200, lambdaOutput.getStatusCode());
        assertEquals(PYI_TECHNICAL_ERROR_PAGE, outputBody.get("page"));
    }

    @Test
    void shouldReturnIpvSuccessPageResponseWhenRequired() throws IOException {
        var input =
                new ApiGatewayTemplateMappingInput(
                        Map.of("input", "body"),
                        Map.of("ipv-session-id", "1234"),
                        Map.of(JOURNEY_STEP, NEXT),
                        Collections.emptyMap());
        InputStream inputStream = new ByteArrayInputStream(objectMapper.writeValueAsBytes(input));
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

        IpvSessionItem ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setIpvSessionId(SecureTokenHelper.generate());
        ipvSessionItem.setCreationDateTime(Instant.now().toString());
        ipvSessionItem.setUserState(CRI_KBV_STATE);
        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);
        when(mockConfigurationService.getSsmParameter(BACKEND_SESSION_TIMEOUT)).thenReturn("7200");

        processJourneyStepHandler.handleRequest(inputStream, outputStream, mockContext);

        ApiGatewayTemplateMappingOutput lambdaOutput =
                objectMapper.readValue(
                        outputStream.toByteArray(), ApiGatewayTemplateMappingOutput.class);
        Map<String, Object> outputBody =
                objectMapper.readValue(lambdaOutput.getBody(), new TypeReference<>() {});

        ArgumentCaptor<IpvSessionItem> sessionArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(mockIpvSessionService).updateIpvSession(sessionArgumentCaptor.capture());
        assertEquals(IPV_SUCCESS_PAGE_STATE, sessionArgumentCaptor.getValue().getUserState());

        assertEquals(200, lambdaOutput.getStatusCode());
        assertEquals(IPV_SUCCESS_PAGE, outputBody.get("page"));
    }

    @Test
    void shouldReturnCriErrorPageResponseIfKbvCriFails() throws IOException {
        var input =
                new ApiGatewayTemplateMappingInput(
                        Map.of("input", "body"),
                        Map.of("ipv-session-id", "1234"),
                        Map.of(JOURNEY_STEP, ERROR),
                        Collections.emptyMap());
        InputStream inputStream = new ByteArrayInputStream(objectMapper.writeValueAsBytes(input));
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

        IpvSessionItem ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setIpvSessionId(SecureTokenHelper.generate());
        ipvSessionItem.setCreationDateTime(Instant.now().toString());
        ipvSessionItem.setUserState(CRI_KBV_STATE);
        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);
        when(mockConfigurationService.getSsmParameter(BACKEND_SESSION_TIMEOUT)).thenReturn("7200");

        processJourneyStepHandler.handleRequest(inputStream, outputStream, mockContext);

        ApiGatewayTemplateMappingOutput lambdaOutput =
                objectMapper.readValue(
                        outputStream.toByteArray(), ApiGatewayTemplateMappingOutput.class);
        Map<String, Object> outputBody =
                objectMapper.readValue(lambdaOutput.getBody(), new TypeReference<>() {});

        ArgumentCaptor<IpvSessionItem> sessionArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(mockIpvSessionService).updateIpvSession(sessionArgumentCaptor.capture());
        assertEquals(CRI_ERROR_STATE, sessionArgumentCaptor.getValue().getUserState());

        assertEquals(200, lambdaOutput.getStatusCode());
        assertEquals(PYI_TECHNICAL_ERROR_PAGE, outputBody.get("page"));
    }

    @Test
    void shouldReturnEndSessionJourneyResponseWhenRequired() throws IOException {
        var input =
                new ApiGatewayTemplateMappingInput(
                        Map.of("input", "body"),
                        Map.of("ipv-session-id", "1234"),
                        Map.of(JOURNEY_STEP, NEXT),
                        Collections.emptyMap());
        InputStream inputStream = new ByteArrayInputStream(objectMapper.writeValueAsBytes(input));
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

        IpvSessionItem ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setIpvSessionId(SecureTokenHelper.generate());
        ipvSessionItem.setCreationDateTime(Instant.now().toString());
        ipvSessionItem.setUserState(IPV_SUCCESS_PAGE_STATE);
        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);
        when(mockConfigurationService.getSsmParameter(BACKEND_SESSION_TIMEOUT)).thenReturn("7200");

        processJourneyStepHandler.handleRequest(inputStream, outputStream, mockContext);

        ApiGatewayTemplateMappingOutput lambdaOutput =
                objectMapper.readValue(
                        outputStream.toByteArray(), ApiGatewayTemplateMappingOutput.class);
        Map<String, Object> outputBody =
                objectMapper.readValue(lambdaOutput.getBody(), new TypeReference<>() {});

        ArgumentCaptor<IpvSessionItem> sessionArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(mockIpvSessionService).updateIpvSession(sessionArgumentCaptor.capture());
        assertEquals(END_STATE, sessionArgumentCaptor.getValue().getUserState());

        assertEquals(200, lambdaOutput.getStatusCode());
        assertEquals("/journey/build-client-oauth-response", outputBody.get("journey"));
    }

    @Test
    void shouldReturnDebugPageResponseWhenRequired() throws IOException {
        var input =
                new ApiGatewayTemplateMappingInput(
                        Map.of("input", "body"),
                        Map.of("ipv-session-id", "1234"),
                        Map.of(JOURNEY_STEP, NEXT),
                        Collections.emptyMap());
        InputStream inputStream = new ByteArrayInputStream(objectMapper.writeValueAsBytes(input));
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

        IpvSessionItem ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setIpvSessionId(SecureTokenHelper.generate());
        ipvSessionItem.setCreationDateTime(Instant.now().toString());
        ipvSessionItem.setUserState(DEBUG_PAGE_STATE);
        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);
        when(mockConfigurationService.getSsmParameter(BACKEND_SESSION_TIMEOUT)).thenReturn("7200");

        processJourneyStepHandler.handleRequest(inputStream, outputStream, mockContext);

        ApiGatewayTemplateMappingOutput lambdaOutput =
                objectMapper.readValue(
                        outputStream.toByteArray(), ApiGatewayTemplateMappingOutput.class);
        Map<String, Object> outputBody =
                objectMapper.readValue(lambdaOutput.getBody(), new TypeReference<>() {});

        assertEquals(200, lambdaOutput.getStatusCode());
        assertEquals(DEBUG_PAGE, outputBody.get("page"));
    }

    @Test
    void shouldReturnPYITechnicalPageIfErrorOccursOnDebugJourney() throws IOException {
        var input =
                new ApiGatewayTemplateMappingInput(
                        Map.of("input", "body"),
                        Map.of("ipv-session-id", "1234"),
                        Map.of(JOURNEY_STEP, ERROR),
                        Collections.emptyMap());
        InputStream inputStream = new ByteArrayInputStream(objectMapper.writeValueAsBytes(input));
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

        IpvSessionItem ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setIpvSessionId(SecureTokenHelper.generate());
        ipvSessionItem.setCreationDateTime(Instant.now().toString());
        ipvSessionItem.setUserState(DEBUG_PAGE_STATE);
        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);
        when(mockConfigurationService.getSsmParameter(BACKEND_SESSION_TIMEOUT)).thenReturn("7200");

        processJourneyStepHandler.handleRequest(inputStream, outputStream, mockContext);

        ApiGatewayTemplateMappingOutput lambdaOutput =
                objectMapper.readValue(
                        outputStream.toByteArray(), ApiGatewayTemplateMappingOutput.class);
        Map<String, Object> outputBody =
                objectMapper.readValue(lambdaOutput.getBody(), new TypeReference<>() {});

        ArgumentCaptor<IpvSessionItem> sessionArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(mockIpvSessionService).updateIpvSession(sessionArgumentCaptor.capture());
        assertEquals(CRI_ERROR_STATE, sessionArgumentCaptor.getValue().getUserState());

        assertEquals(200, lambdaOutput.getStatusCode());
        assertEquals(PYI_TECHNICAL_ERROR_PAGE, outputBody.get("page"));
    }

    @Test
    void shouldReturnPYINoMatchPageIfErrorOccursOnDebugJourney() throws IOException {
        var input =
                new ApiGatewayTemplateMappingInput(
                        Map.of("input", "body"),
                        Map.of("ipv-session-id", "1234"),
                        Map.of(JOURNEY_STEP, FAIL),
                        Collections.emptyMap());
        InputStream inputStream = new ByteArrayInputStream(objectMapper.writeValueAsBytes(input));
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

        IpvSessionItem ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setIpvSessionId(SecureTokenHelper.generate());
        ipvSessionItem.setCreationDateTime(Instant.now().toString());
        ipvSessionItem.setUserState(DEBUG_PAGE_STATE);
        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);
        when(mockConfigurationService.getSsmParameter(BACKEND_SESSION_TIMEOUT)).thenReturn("7200");

        processJourneyStepHandler.handleRequest(inputStream, outputStream, mockContext);

        ApiGatewayTemplateMappingOutput lambdaOutput =
                objectMapper.readValue(
                        outputStream.toByteArray(), ApiGatewayTemplateMappingOutput.class);
        Map<String, Object> outputBody =
                objectMapper.readValue(lambdaOutput.getBody(), new TypeReference<>() {});

        ArgumentCaptor<IpvSessionItem> sessionArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(mockIpvSessionService).updateIpvSession(sessionArgumentCaptor.capture());
        assertEquals(PYI_NO_MATCH_STATE, sessionArgumentCaptor.getValue().getUserState());

        assertEquals(200, lambdaOutput.getStatusCode());
        assertEquals(PYI_NO_MATCH_PAGE, outputBody.get("page"));
    }

    @Test
    void shouldReturnErrorPageResponseWhenRequired() throws IOException {
        var input =
                new ApiGatewayTemplateMappingInput(
                        Map.of("input", "body"),
                        Map.of("ipv-session-id", "1234"),
                        Map.of(JOURNEY_STEP, NEXT),
                        Collections.emptyMap());
        InputStream inputStream = new ByteArrayInputStream(objectMapper.writeValueAsBytes(input));
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

        IpvSessionItem ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setIpvSessionId(SecureTokenHelper.generate());
        ipvSessionItem.setCreationDateTime(Instant.now().toString());
        ipvSessionItem.setUserState(CRI_ERROR_STATE);
        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);
        when(mockConfigurationService.getSsmParameter(BACKEND_SESSION_TIMEOUT)).thenReturn("7200");

        processJourneyStepHandler.handleRequest(inputStream, outputStream, mockContext);

        ApiGatewayTemplateMappingOutput lambdaOutput =
                objectMapper.readValue(
                        outputStream.toByteArray(), ApiGatewayTemplateMappingOutput.class);
        Map<String, Object> outputBody =
                objectMapper.readValue(lambdaOutput.getBody(), new TypeReference<>() {});

        assertEquals(200, lambdaOutput.getStatusCode());
        assertEquals("/journey/build-client-oauth-response", outputBody.get("journey"));
    }

    @Test
    void shouldReturnPYINoMatchPageIfPassportCriVCValidationReturnsFail() throws IOException {
        var input =
                new ApiGatewayTemplateMappingInput(
                        Map.of("input", "body"),
                        Map.of("ipv-session-id", "1234"),
                        Map.of(JOURNEY_STEP, FAIL),
                        Collections.emptyMap());
        InputStream inputStream = new ByteArrayInputStream(objectMapper.writeValueAsBytes(input));
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

        IpvSessionItem ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setIpvSessionId(SecureTokenHelper.generate());
        ipvSessionItem.setCreationDateTime(Instant.now().toString());
        ipvSessionItem.setUserState(CRI_UK_PASSPORT_STATE);
        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);
        when(mockConfigurationService.getSsmParameter(BACKEND_SESSION_TIMEOUT)).thenReturn("7200");

        processJourneyStepHandler.handleRequest(inputStream, outputStream, mockContext);

        ApiGatewayTemplateMappingOutput lambdaOutput =
                objectMapper.readValue(
                        outputStream.toByteArray(), ApiGatewayTemplateMappingOutput.class);
        Map<String, Object> outputBody =
                objectMapper.readValue(lambdaOutput.getBody(), new TypeReference<>() {});

        ArgumentCaptor<IpvSessionItem> sessionArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(mockIpvSessionService).updateIpvSession(sessionArgumentCaptor.capture());
        assertEquals(PYI_NO_MATCH_STATE, sessionArgumentCaptor.getValue().getUserState());

        assertEquals(200, lambdaOutput.getStatusCode());
        assertEquals(PYI_NO_MATCH_PAGE, outputBody.get("page"));
    }

    @Test
    void shouldReturnPYINoMatchPageIfFraudCriVCValidationReturnsFail() throws IOException {
        var input =
                new ApiGatewayTemplateMappingInput(
                        Map.of("input", "body"),
                        Map.of("ipv-session-id", "1234"),
                        Map.of(JOURNEY_STEP, FAIL),
                        Collections.emptyMap());
        InputStream inputStream = new ByteArrayInputStream(objectMapper.writeValueAsBytes(input));
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

        IpvSessionItem ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setIpvSessionId(SecureTokenHelper.generate());
        ipvSessionItem.setCreationDateTime(Instant.now().toString());
        ipvSessionItem.setUserState(CRI_FRAUD_STATE);
        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);
        when(mockConfigurationService.getSsmParameter(BACKEND_SESSION_TIMEOUT)).thenReturn("7200");

        processJourneyStepHandler.handleRequest(inputStream, outputStream, mockContext);

        ApiGatewayTemplateMappingOutput lambdaOutput =
                objectMapper.readValue(
                        outputStream.toByteArray(), ApiGatewayTemplateMappingOutput.class);
        Map<String, Object> outputBody =
                objectMapper.readValue(lambdaOutput.getBody(), new TypeReference<>() {});

        ArgumentCaptor<IpvSessionItem> sessionArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(mockIpvSessionService).updateIpvSession(sessionArgumentCaptor.capture());
        assertEquals(PYI_NO_MATCH_STATE, sessionArgumentCaptor.getValue().getUserState());

        assertEquals(200, lambdaOutput.getStatusCode());
        assertEquals(PYI_NO_MATCH_PAGE, outputBody.get("page"));
    }

    @Test
    void shouldReturnPYIKbvFailPageIfKbvCriVCValidationReturnsFail() throws IOException {
        var input =
                new ApiGatewayTemplateMappingInput(
                        Map.of("input", "body"),
                        Map.of("ipv-session-id", "1234"),
                        Map.of(JOURNEY_STEP, FAIL),
                        Collections.emptyMap());
        InputStream inputStream = new ByteArrayInputStream(objectMapper.writeValueAsBytes(input));
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

        IpvSessionItem ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setIpvSessionId(SecureTokenHelper.generate());
        ipvSessionItem.setCreationDateTime(Instant.now().toString());
        ipvSessionItem.setUserState(CRI_KBV_STATE);
        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);
        when(mockConfigurationService.getSsmParameter(BACKEND_SESSION_TIMEOUT)).thenReturn("7200");

        processJourneyStepHandler.handleRequest(inputStream, outputStream, mockContext);

        ApiGatewayTemplateMappingOutput lambdaOutput =
                objectMapper.readValue(
                        outputStream.toByteArray(), ApiGatewayTemplateMappingOutput.class);
        Map<String, Object> outputBody =
                objectMapper.readValue(lambdaOutput.getBody(), new TypeReference<>() {});

        ArgumentCaptor<IpvSessionItem> sessionArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(mockIpvSessionService).updateIpvSession(sessionArgumentCaptor.capture());
        assertEquals(PYI_KBV_FAIL_STATE, sessionArgumentCaptor.getValue().getUserState());

        assertEquals(200, lambdaOutput.getStatusCode());
        assertEquals(PYI_KBV_FAIL_PAGE, outputBody.get("page"));
    }

    @Test
    void shouldReturnErrorPageIfSessionHasExpired() throws Exception {
        var input =
                new ApiGatewayTemplateMappingInput(
                        Map.of("input", "body"),
                        Map.of("ipv-session-id", "1234"),
                        Map.of(JOURNEY_STEP, NEXT),
                        Collections.emptyMap());
        InputStream inputStream = new ByteArrayInputStream(objectMapper.writeValueAsBytes(input));
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

        IpvSessionItem ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setIpvSessionId(SecureTokenHelper.generate());
        ipvSessionItem.setCreationDateTime(Instant.now().minusSeconds(100).toString());
        ipvSessionItem.setUserState(CRI_UK_PASSPORT_STATE);
        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);
        when(mockConfigurationService.getSsmParameter(BACKEND_SESSION_TIMEOUT)).thenReturn("99");

        processJourneyStepHandler.handleRequest(inputStream, outputStream, mockContext);

        ApiGatewayTemplateMappingOutput lambdaOutput =
                objectMapper.readValue(
                        outputStream.toByteArray(), ApiGatewayTemplateMappingOutput.class);
        Map<String, Object> outputBody =
                objectMapper.readValue(lambdaOutput.getBody(), new TypeReference<>() {});

        ArgumentCaptor<IpvSessionItem> sessionArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(mockIpvSessionService).updateIpvSession(sessionArgumentCaptor.capture());

        IpvSessionItem capturedIpvSessionItem = sessionArgumentCaptor.getValue();
        assertEquals(CORE_SESSION_TIMEOUT_STATE, capturedIpvSessionItem.getUserState());
        assertEquals(OAuth2Error.ACCESS_DENIED.getCode(), capturedIpvSessionItem.getErrorCode());
        assertEquals(
                OAuth2Error.ACCESS_DENIED.getDescription(),
                capturedIpvSessionItem.getErrorDescription());

        assertEquals(200, lambdaOutput.getStatusCode());
        assertEquals(PYI_TECHNICAL_ERROR_PAGE, outputBody.get("page"));
    }

    @Test
    void shouldReturnSessionEndJourneyIfStateIsSessionTimeout() throws Exception {
        var input =
                new ApiGatewayTemplateMappingInput(
                        Map.of("input", "body"),
                        Map.of("ipv-session-id", "1234"),
                        Map.of(JOURNEY_STEP, NEXT),
                        Collections.emptyMap());
        InputStream inputStream = new ByteArrayInputStream(objectMapper.writeValueAsBytes(input));
        ByteArrayOutputStream outputStream = new ByteArrayOutputStream();

        IpvSessionItem ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setIpvSessionId(SecureTokenHelper.generate());
        ipvSessionItem.setCreationDateTime(Instant.now().toString());
        ipvSessionItem.setUserState(CORE_SESSION_TIMEOUT_STATE);
        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);

        processJourneyStepHandler.handleRequest(inputStream, outputStream, mockContext);

        ApiGatewayTemplateMappingOutput lambdaOutput =
                objectMapper.readValue(
                        outputStream.toByteArray(), ApiGatewayTemplateMappingOutput.class);
        Map<String, Object> outputBody =
                objectMapper.readValue(lambdaOutput.getBody(), new TypeReference<>() {});

        assertEquals(200, lambdaOutput.getStatusCode());
        assertEquals("/journey/build-client-oauth-response", outputBody.get("journey"));
    }
}
