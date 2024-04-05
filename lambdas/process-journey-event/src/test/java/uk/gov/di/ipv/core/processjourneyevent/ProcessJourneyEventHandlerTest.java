package uk.gov.di.ipv.core.processjourneyevent;

import com.amazonaws.services.lambda.runtime.Context;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import org.apache.http.HttpStatus;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.auditing.AuditEvent;
import uk.gov.di.ipv.core.library.auditing.AuditEventTypes;
import uk.gov.di.ipv.core.library.auditing.extension.AuditExtensionMitigationType;
import uk.gov.di.ipv.core.library.auditing.extension.AuditExtensionSubjourneyType;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.IpvJourneyTypes;
import uk.gov.di.ipv.core.library.domain.JourneyRequest;
import uk.gov.di.ipv.core.library.helpers.SecureTokenHelper;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.ClientOAuthSessionDetailsService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.StateMachineInitializerMode;

import java.io.IOException;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.BACKEND_SESSION_TIMEOUT;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.COMPONENT_ID;
import static uk.gov.di.ipv.core.library.domain.IpvJourneyTypes.INITIAL_JOURNEY_SELECTION;
import static uk.gov.di.ipv.core.library.domain.IpvJourneyTypes.SESSION_TIMEOUT;
import static uk.gov.di.ipv.core.library.domain.IpvJourneyTypes.TECHNICAL_ERROR;

@ExtendWith(MockitoExtension.class)
class ProcessJourneyEventHandlerTest {
    private static final String JOURNEY_NEXT = "/journey/next";
    private static final String JOURNEY_EVENT_ONE_WITH_TEST_CURRENT_PAGE =
            "/journey/eventOne?currentPage=testCurrentPage";
    private static final String JOURNEY_TEST_WITH_CONTEXT_WITH_MISSING_CURRENT_PAGE =
            "/journey/testWithContext";
    private static final String JOURNEY_TEST_WITH_CONTEXT_WITH_EMPTY_CURRENT_PAGE =
            "/journey/testWithContext?currentPage=";
    private static final String JOURNEY_EVENT_TWO_WITH_CORRECT_CURRENT_PAGE =
            "/journey/eventTwo?currentPage=page-id-for-some-page";
    private static final String TEST_IP = "1.2.3.4";
    private static final String TEST_SESSION_ID = "test-session-id";
    private static final String TIMEOUT_UNRECOVERABLE_STATE = "TIMEOUT_UNRECOVERABLE_PAGE";
    private static final String PYI_UNRECOVERABLE_TIMEOUT_ERROR_PAGE = "pyi-timeout-unrecoverable";
    private static final String CODE = "code";
    private static final String JOURNEY = "journey";
    private static final String MESSAGE = "message";
    private static final String STATUS_CODE = "statusCode";

    @Mock private Context mockContext;
    @Mock private IpvSessionService mockIpvSessionService;
    @Mock private ConfigService mockConfigService;
    @Mock private AuditService mockAuditService;
    @Mock private ClientOAuthSessionDetailsService mockClientOAuthSessionService;
    @Captor private ArgumentCaptor<AuditEvent> auditEventCaptor;

    @Test
    void shouldReturn400OnMissingJourneyStep() throws Exception {
        var input = JourneyRequest.builder().ipAddress(TEST_IP).ipvSessionId(TEST_IP).build();

        Map<String, Object> output =
                getProcessJourneyStepHandler().handleRequest(input, mockContext);

        assertEquals(HttpStatus.SC_BAD_REQUEST, output.get(STATUS_CODE));
        assertEquals(ErrorResponse.MISSING_JOURNEY_EVENT.getCode(), output.get(CODE));
        assertEquals(ErrorResponse.MISSING_JOURNEY_EVENT.getMessage(), output.get(MESSAGE));
    }

    @Test
    void shouldReturn400OnMissingSessionIdParam() throws Exception {
        var input = JourneyRequest.builder().ipAddress(TEST_IP).journey(JOURNEY_NEXT).build();

        Map<String, Object> output =
                getProcessJourneyStepHandler().handleRequest(input, mockContext);

        assertEquals(HttpStatus.SC_BAD_REQUEST, output.get(STATUS_CODE));
        assertEquals(ErrorResponse.MISSING_IPV_SESSION_ID.getCode(), output.get(CODE));
        assertEquals(ErrorResponse.MISSING_IPV_SESSION_ID.getMessage(), output.get(MESSAGE));
    }

    @Test
    void shouldReturn400WhenInvalidSessionIdProvided() throws Exception {
        var input =
                JourneyRequest.builder()
                        .ipAddress(TEST_IP)
                        .journey(JOURNEY_NEXT)
                        .ipvSessionId(TEST_IP)
                        .build();

        Map<String, Object> output =
                getProcessJourneyStepHandler().handleRequest(input, mockContext);

        assertEquals(HttpStatus.SC_BAD_REQUEST, output.get(STATUS_CODE));
        assertEquals(ErrorResponse.INVALID_SESSION_ID.getCode(), output.get(CODE));
        assertEquals(ErrorResponse.INVALID_SESSION_ID.getMessage(), output.get(MESSAGE));
    }

    @Test
    void shouldReturn500WhenUnknownJourneyEngineStepProvided() throws Exception {
        var input =
                JourneyRequest.builder()
                        .ipAddress(TEST_IP)
                        .journey("invalid-event")
                        .ipvSessionId(TEST_IP)
                        .build();

        mockIpvSessionItemAndTimeout("START");

        Map<String, Object> output =
                getProcessJourneyStepHandler().handleRequest(input, mockContext);

        assertEquals(HttpStatus.SC_INTERNAL_SERVER_ERROR, output.get(STATUS_CODE));
        assertEquals(ErrorResponse.FAILED_JOURNEY_ENGINE_STEP.getCode(), output.get(CODE));
        assertEquals(ErrorResponse.FAILED_JOURNEY_ENGINE_STEP.getMessage(), output.get(MESSAGE));
    }

    @Test
    void shouldReturn500WhenUserIsInUnknownState() throws Exception {
        var input =
                JourneyRequest.builder()
                        .ipAddress(TEST_IP)
                        .journey(JOURNEY_NEXT)
                        .ipvSessionId(TEST_IP)
                        .build();

        mockIpvSessionItemAndTimeout("INVALIDSTATE");

        Map<String, Object> output =
                getProcessJourneyStepHandler().handleRequest(input, mockContext);

        assertEquals(HttpStatus.SC_INTERNAL_SERVER_ERROR, output.get(STATUS_CODE));
        assertEquals(ErrorResponse.FAILED_JOURNEY_ENGINE_STEP.getCode(), output.get(CODE));
        assertEquals(ErrorResponse.FAILED_JOURNEY_ENGINE_STEP.getMessage(), output.get(MESSAGE));
    }

    @Test
    void shouldReturn500IfNoStateMachineMatchingJourneyType() throws IOException {
        var input =
                JourneyRequest.builder()
                        .ipAddress(TEST_IP)
                        .journey(JOURNEY_NEXT)
                        .ipvSessionId(TEST_IP)
                        .build();

        mockIpvSessionItemAndTimeout("START");

        ProcessJourneyEventHandler processJourneyEventHandler =
                new ProcessJourneyEventHandler(
                        mockAuditService,
                        mockIpvSessionService,
                        mockConfigService,
                        mockClientOAuthSessionService,
                        List.of(),
                        StateMachineInitializerMode.STANDARD);

        Map<String, Object> output = processJourneyEventHandler.handleRequest(input, mockContext);

        assertEquals(HttpStatus.SC_INTERNAL_SERVER_ERROR, output.get(STATUS_CODE));
        assertEquals(ErrorResponse.FAILED_JOURNEY_ENGINE_STEP.getCode(), output.get(CODE));
        assertEquals(ErrorResponse.FAILED_JOURNEY_ENGINE_STEP.getMessage(), output.get(MESSAGE));
    }

    @Test
    void shouldReturnCurrentStateIfPageOutOfSync() throws IOException {
        var input =
                JourneyRequest.builder()
                        .ipAddress(TEST_IP)
                        .journey(JOURNEY_EVENT_ONE_WITH_TEST_CURRENT_PAGE)
                        .ipvSessionId(TEST_IP)
                        .build();

        mockIpvSessionItemAndTimeout("PAGE_STATE");

        ProcessJourneyEventHandler processJourneyEventHandler =
                new ProcessJourneyEventHandler(
                        mockAuditService,
                        mockIpvSessionService,
                        mockConfigService,
                        mockClientOAuthSessionService,
                        List.of(INITIAL_JOURNEY_SELECTION, TECHNICAL_ERROR),
                        StateMachineInitializerMode.TEST);

        Map<String, Object> output = processJourneyEventHandler.handleRequest(input, mockContext);

        assertEquals("page-id-for-some-page", output.get("page"));
    }

    @Test
    void shouldReturnNextStateIfInSync() throws IOException {
        var input =
                JourneyRequest.builder()
                        .ipAddress(TEST_IP)
                        .journey(JOURNEY_EVENT_TWO_WITH_CORRECT_CURRENT_PAGE)
                        .ipvSessionId(TEST_IP)
                        .build();

        when(mockConfigService.isEnabled("aCriId")).thenReturn(true);

        mockIpvSessionItemAndTimeout("PAGE_STATE");

        ProcessJourneyEventHandler processJourneyEventHandler =
                new ProcessJourneyEventHandler(
                        mockAuditService,
                        mockIpvSessionService,
                        mockConfigService,
                        mockClientOAuthSessionService,
                        List.of(INITIAL_JOURNEY_SELECTION, TECHNICAL_ERROR),
                        StateMachineInitializerMode.TEST);

        Map<String, Object> output = processJourneyEventHandler.handleRequest(input, mockContext);

        assertEquals("/journey/cri/build-oauth-request/aCriId", output.get("journey"));
    }

    @ParameterizedTest()
    @MethodSource("journeyUrisWithCurrentPageForCri")
    void shouldTransitionCriStateIfCurrentPageMatchesCriId(
            String journeyUri, String expectedNewJourneyState) throws IOException {
        var input =
                JourneyRequest.builder()
                        .ipAddress(TEST_IP)
                        .journey(journeyUri)
                        .ipvSessionId(TEST_IP)
                        .build();

        mockIpvSessionItemAndTimeout("CRI_STATE");

        ProcessJourneyEventHandler processJourneyEventHandler =
                new ProcessJourneyEventHandler(
                        mockAuditService,
                        mockIpvSessionService,
                        mockConfigService,
                        mockClientOAuthSessionService,
                        List.of(INITIAL_JOURNEY_SELECTION, TECHNICAL_ERROR),
                        StateMachineInitializerMode.TEST);

        Map<String, Object> output = processJourneyEventHandler.handleRequest(input, mockContext);

        assertEquals(expectedNewJourneyState, output.get("journey"));
    }

    private static Stream<Arguments> journeyUrisWithCurrentPageForCri() {
        return Stream.of(
                Arguments.of(
                        JOURNEY_TEST_WITH_CONTEXT_WITH_MISSING_CURRENT_PAGE,
                        "/journey/cri/build-oauth-request/aCriId?context=test_context"),
                Arguments.of(
                        JOURNEY_EVENT_ONE_WITH_TEST_CURRENT_PAGE,
                        "/journey/cri/build-oauth-request/aCriId"),
                Arguments.of(
                        JOURNEY_EVENT_ONE_WITH_TEST_CURRENT_PAGE,
                        "/journey/cri/build-oauth-request/aCriId"),
                Arguments.of(
                        JOURNEY_TEST_WITH_CONTEXT_WITH_EMPTY_CURRENT_PAGE,
                        "/journey/cri/build-oauth-request/aCriId?context=test_context"));
    }

    @Test
    void shouldThrowErrorIfJourneyEventDuringProcess() throws IOException {
        var input =
                JourneyRequest.builder()
                        .ipAddress(TEST_IP)
                        .journey(JOURNEY_EVENT_ONE_WITH_TEST_CURRENT_PAGE)
                        .ipvSessionId(TEST_IP)
                        .build();

        mockIpvSessionItemAndTimeout("PROCESS_STATE");

        ProcessJourneyEventHandler processJourneyEventHandler =
                new ProcessJourneyEventHandler(
                        mockAuditService,
                        mockIpvSessionService,
                        mockConfigService,
                        mockClientOAuthSessionService,
                        List.of(INITIAL_JOURNEY_SELECTION, TECHNICAL_ERROR),
                        StateMachineInitializerMode.TEST);

        Map<String, Object> output = processJourneyEventHandler.handleRequest(input, mockContext);

        assertEquals(HttpStatus.SC_INTERNAL_SERVER_ERROR, output.get(STATUS_CODE));
        assertEquals(ErrorResponse.FAILED_JOURNEY_ENGINE_STEP.getCode(), output.get(CODE));
        assertEquals(ErrorResponse.FAILED_JOURNEY_ENGINE_STEP.getMessage(), output.get(MESSAGE));
    }

    @Test
    void shouldReturnErrorPageIfSessionHasExpired() throws Exception {
        var input =
                JourneyRequest.builder()
                        .ipAddress(TEST_IP)
                        .journey(JOURNEY_NEXT)
                        .ipvSessionId(TEST_IP)
                        .build();

        mockIpvSessionItemAndTimeout("CRI_STATE");
        IpvSessionItem ipvSessionItem = mockIpvSessionService.getIpvSession(TEST_IP);
        ipvSessionItem.setCreationDateTime(Instant.now().minusSeconds(100).toString());
        when(mockConfigService.getSsmParameter(BACKEND_SESSION_TIMEOUT)).thenReturn("99");

        Map<String, Object> output =
                getProcessJourneyStepHandler().handleRequest(input, mockContext);

        ArgumentCaptor<IpvSessionItem> sessionArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(mockIpvSessionService).updateIpvSession(sessionArgumentCaptor.capture());

        IpvSessionItem capturedIpvSessionItem = sessionArgumentCaptor.getValue();
        assertEquals(SESSION_TIMEOUT, sessionArgumentCaptor.getValue().getJourneyType());
        assertEquals(TIMEOUT_UNRECOVERABLE_STATE, sessionArgumentCaptor.getValue().getUserState());
        assertEquals(OAuth2Error.ACCESS_DENIED.getCode(), capturedIpvSessionItem.getErrorCode());
        assertEquals(
                OAuth2Error.ACCESS_DENIED.getDescription(),
                capturedIpvSessionItem.getErrorDescription());

        assertEquals(PYI_UNRECOVERABLE_TIMEOUT_ERROR_PAGE, output.get("page"));

        verify(mockAuditService).sendAuditEvent(auditEventCaptor.capture());
        var capturedAuditEvent = auditEventCaptor.getValue();

        assertEquals(AuditEventTypes.IPV_SUBJOURNEY_START, capturedAuditEvent.getEventName());
        assertEquals(
                SESSION_TIMEOUT,
                ((AuditExtensionSubjourneyType) capturedAuditEvent.getExtensions()).journeyType());
        assertEquals("core", capturedAuditEvent.getComponentId());
        assertEquals("testuserid", capturedAuditEvent.getUser().getUserId());
        assertEquals("testjourneyid", capturedAuditEvent.getUser().getGovukSigninJourneyId());
    }

    @Test
    void shouldReturnSessionEndJourneyIfStateIsSessionTimeout() throws Exception {
        var input =
                JourneyRequest.builder()
                        .ipAddress(TEST_IP)
                        .journey(JOURNEY_NEXT)
                        .ipvSessionId(TEST_IP)
                        .build();

        IpvSessionItem ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setIpvSessionId(SecureTokenHelper.getInstance().generate());
        ipvSessionItem.setCreationDateTime(Instant.now().toString());
        ipvSessionItem.setClientOAuthSessionId(SecureTokenHelper.getInstance().generate());
        ipvSessionItem.setJourneyType(SESSION_TIMEOUT);
        ipvSessionItem.setUserState(TIMEOUT_UNRECOVERABLE_STATE);

        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);
        when(mockClientOAuthSessionService.getClientOAuthSession(any()))
                .thenReturn(getClientOAuthSessionItem());

        Map<String, Object> output =
                getProcessJourneyStepHandler().handleRequest(input, mockContext);

        assertEquals("/journey/build-client-oauth-response", output.get("journey"));
    }

    @Test
    void shouldClearOauthSessionIfItExists() throws Exception {
        var input =
                JourneyRequest.builder()
                        .ipAddress(TEST_IP)
                        .journey(JOURNEY_NEXT)
                        .ipvSessionId(TEST_IP)
                        .build();

        mockIpvSessionItemAndTimeout("START");

        getProcessJourneyStepHandler().handleRequest(input, mockContext);

        ArgumentCaptor<IpvSessionItem> sessionArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(mockIpvSessionService).updateIpvSession(sessionArgumentCaptor.capture());
        assertNull(sessionArgumentCaptor.getValue().getCriOAuthSessionId());
    }

    @ParameterizedTest
    @MethodSource("journeyUriParameters")
    void shouldIncludeParametersInJourneyUriIfExists(String journeyEvent, String expectedJourneyUri)
            throws Exception {
        var input =
                JourneyRequest.builder()
                        .ipAddress(TEST_IP)
                        .journey(journeyEvent)
                        .ipvSessionId(TEST_IP)
                        .build();

        mockIpvSessionItemAndTimeout("CRI_STATE");

        Map<String, Object> processJourneyEventOutput =
                getProcessJourneyStepHandler(StateMachineInitializerMode.TEST)
                        .handleRequest(input, mockContext);

        assertEquals(
                expectedJourneyUri,
                processJourneyEventOutput.get(JOURNEY),
                () ->
                        String.format(
                                "Expected journey URI for event %s to be %s, but found %s",
                                journeyEvent,
                                expectedJourneyUri,
                                processJourneyEventOutput.get(JOURNEY)));
    }

    private static Stream<Arguments> journeyUriParameters() {
        return Stream.of(
                Arguments.of(
                        "testWithContext",
                        "/journey/cri/build-oauth-request/aCriId?context=test_context"),
                Arguments.of(
                        "testWithScope",
                        "/journey/cri/build-oauth-request/aCriId?scope=test_scope"),
                Arguments.of(
                        "testWithContextAndScope",
                        "/journey/cri/build-oauth-request/aCriId?context=test_context&scope=test_scope"));
    }

    @Test
    void shouldFollowJourneyChanges() throws Exception {
        // arrange
        mockIpvSessionItemAndTimeout("CRI_STATE");
        var input =
                JourneyRequest.builder()
                        .ipAddress(TEST_IP)
                        .journey("testJourneyStep")
                        .ipvSessionId(TEST_SESSION_ID)
                        .build();

        // act
        var output =
                getProcessJourneyStepHandler(StateMachineInitializerMode.TEST)
                        .handleRequest(input, mockContext);

        // assert
        assertEquals("technical-error-page", output.get("page"));
        assertEquals(
                TECHNICAL_ERROR,
                mockIpvSessionService.getIpvSession(TEST_SESSION_ID).getJourneyType());

        verify(mockAuditService).sendAuditEvent(auditEventCaptor.capture());
        var capturedAuditEvent = auditEventCaptor.getValue();

        assertEquals(AuditEventTypes.IPV_SUBJOURNEY_START, capturedAuditEvent.getEventName());
        assertEquals(
                IpvJourneyTypes.TECHNICAL_ERROR,
                ((AuditExtensionSubjourneyType) capturedAuditEvent.getExtensions()).journeyType());
        assertEquals("core", capturedAuditEvent.getComponentId());
        assertEquals("testuserid", capturedAuditEvent.getUser().getUserId());
        assertEquals("testjourneyid", capturedAuditEvent.getUser().getGovukSigninJourneyId());
    }

    @Test
    void shouldSendAuditEventForMitigationStart() throws Exception {
        var input =
                JourneyRequest.builder()
                        .ipAddress(TEST_IP)
                        .journey("testWithMitigationStart")
                        .ipvSessionId(TEST_IP)
                        .build();
        mockIpvSessionItemAndTimeout("CRI_STATE");

        getProcessJourneyStepHandler(StateMachineInitializerMode.TEST)
                .handleRequest(input, mockContext);

        verify(mockAuditService).sendAuditEvent(auditEventCaptor.capture());
        AuditEvent capturedAuditEvent = auditEventCaptor.getValue();

        assertEquals(AuditEventTypes.IPV_MITIGATION_START, capturedAuditEvent.getEventName());
        assertEquals("core", capturedAuditEvent.getComponentId());
        assertEquals("testuserid", capturedAuditEvent.getUser().getUserId());
        assertEquals("testjourneyid", capturedAuditEvent.getUser().getGovukSigninJourneyId());
        assertEquals(
                "a-mitigation-type",
                ((AuditExtensionMitigationType) capturedAuditEvent.getExtensions())
                        .mitigationType());
    }

    private void mockIpvSessionItemAndTimeout(String userState) {
        IpvSessionItem ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setIpvSessionId(SecureTokenHelper.getInstance().generate());
        ipvSessionItem.setCreationDateTime(Instant.now().toString());
        ipvSessionItem.setUserState(userState);
        ipvSessionItem.setClientOAuthSessionId(SecureTokenHelper.getInstance().generate());
        ipvSessionItem.setJourneyType(INITIAL_JOURNEY_SELECTION);

        when(mockConfigService.getSsmParameter(COMPONENT_ID)).thenReturn("core");
        when(mockConfigService.getSsmParameter(BACKEND_SESSION_TIMEOUT)).thenReturn("7200");
        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);
        when(mockClientOAuthSessionService.getClientOAuthSession(any()))
                .thenReturn(getClientOAuthSessionItem());
    }

    private ClientOAuthSessionItem getClientOAuthSessionItem() {
        return ClientOAuthSessionItem.builder()
                .clientOAuthSessionId(SecureTokenHelper.getInstance().generate())
                .responseType("code")
                .state("teststate")
                .redirectUri("https://example.com/redirect")
                .govukSigninJourneyId("testjourneyid")
                .userId("testuserid")
                .build();
    }

    private ProcessJourneyEventHandler getProcessJourneyStepHandler(
            StateMachineInitializerMode stateMachineInitializerMode) throws IOException {
        var journeyTypes =
                stateMachineInitializerMode.equals(StateMachineInitializerMode.TEST)
                        ? List.of(INITIAL_JOURNEY_SELECTION, TECHNICAL_ERROR)
                        : List.of(IpvJourneyTypes.values());

        return new ProcessJourneyEventHandler(
                mockAuditService,
                mockIpvSessionService,
                mockConfigService,
                mockClientOAuthSessionService,
                journeyTypes,
                stateMachineInitializerMode);
    }

    private ProcessJourneyEventHandler getProcessJourneyStepHandler() throws IOException {
        return getProcessJourneyStepHandler(StateMachineInitializerMode.STANDARD);
    }
}
