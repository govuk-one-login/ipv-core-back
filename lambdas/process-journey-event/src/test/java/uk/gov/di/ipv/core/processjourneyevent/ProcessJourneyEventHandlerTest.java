package uk.gov.di.ipv.core.processjourneyevent;

import com.amazonaws.services.lambda.runtime.Context;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.TestInfo;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.InOrder;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import software.amazon.awssdk.http.HttpStatusCode;
import uk.gov.di.ipv.core.library.auditing.AuditEvent;
import uk.gov.di.ipv.core.library.auditing.AuditEventTypes;
import uk.gov.di.ipv.core.library.auditing.extension.AuditExtensionMitigationType;
import uk.gov.di.ipv.core.library.auditing.extension.AuditExtensionSubjourneyType;
import uk.gov.di.ipv.core.library.auditing.extension.AuditExtensionSuccessful;
import uk.gov.di.ipv.core.library.auditing.extension.AuditExtensionUserDetailsUpdateSelected;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.IpvJourneyTypes;
import uk.gov.di.ipv.core.library.domain.JourneyRequest;
import uk.gov.di.ipv.core.library.domain.JourneyState;
import uk.gov.di.ipv.core.library.domain.ScopeConstants;
import uk.gov.di.ipv.core.library.exceptions.CiExtractionException;
import uk.gov.di.ipv.core.library.exceptions.CredentialParseException;
import uk.gov.di.ipv.core.library.exceptions.IpvSessionNotFoundException;
import uk.gov.di.ipv.core.library.helpers.SecureTokenHelper;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.CimitUtilityService;
import uk.gov.di.ipv.core.library.service.ClientOAuthSessionDetailsService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.testhelpers.unit.LogCollector;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.NestedJourneyTypes;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.StateMachineInitializerMode;

import java.io.IOException;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.StringContains.containsString;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.reset;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.auditing.AuditEventTypes.IPV_NO_PHOTO_ID_JOURNEY_START;
import static uk.gov.di.ipv.core.library.domain.IpvJourneyTypes.INITIAL_JOURNEY_SELECTION;
import static uk.gov.di.ipv.core.library.domain.IpvJourneyTypes.SESSION_TIMEOUT;
import static uk.gov.di.ipv.core.library.domain.IpvJourneyTypes.TECHNICAL_ERROR;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.SIGNED_CONTRA_INDICATOR_VC_1;

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
            "/journey/eventTwo?currentPage=page-id-for-page-state";
    private static final String JOURNEY_BUILD_CLIENT_OAUTH_RESPONSE =
            "/journey/build-client-oauth-response";
    private static final String TEST_IP = "1.2.3.4";
    private static final String TEST_SESSION_ID = "test-session-id";
    private static final String TIMEOUT_UNRECOVERABLE_STATE = "TIMEOUT_UNRECOVERABLE_PAGE";
    private static final String PYI_UNRECOVERABLE_TIMEOUT_ERROR_PAGE = "pyi-timeout-unrecoverable";
    private static final String CODE = "errorCode";
    private static final String JOURNEY = "journey";
    private static final String MESSAGE = "errorMessage";
    private static final String STATUS_CODE = "statusCode";
    private static final String SKIP_CHECK_AUDIT_EVENT_WAIT_TAG = "skipCheckAuditEventWait";
    private static final List<String> TEST_NESTED_JOURNEY_TYPES =
            List.of(
                    "nested-journey-definition",
                    "doubly-nested-definition",
                    "strategic-app-triage");
    private static final List<String> REAL_NESTED_JOURNEY_TYPES =
            Stream.of(NestedJourneyTypes.values()).map(NestedJourneyTypes::getJourneyName).toList();
    private static final String TEST_USER_ID = "testuserid";
    private static final String TEST_EVCS_ACCESS_TOKEN = "test-evcs-access-token";

    @Mock private Context mockContext;
    @Mock private IpvSessionService mockIpvSessionService;
    @Mock private ConfigService mockConfigService;
    @Mock private AuditService mockAuditService;
    @Mock private ClientOAuthSessionDetailsService mockClientOAuthSessionService;
    @Mock private CimitUtilityService mockCimitUtilityService;
    @Captor private ArgumentCaptor<AuditEvent> auditEventCaptor;

    @BeforeEach
    void setUp() {
        when(mockConfigService.getComponentId()).thenReturn("https://core-component.example");
    }

    @AfterEach
    void checkAuditEventWait(TestInfo testInfo) {
        if (!testInfo.getTags().contains(SKIP_CHECK_AUDIT_EVENT_WAIT_TAG)) {
            // Assert that no audit events were logged after awaiting the events
            InOrder auditInOrder = inOrder(mockAuditService);
            auditInOrder.verify(mockAuditService).awaitAuditEvents();
            auditInOrder.verifyNoMoreInteractions();
        }
    }

    @Test
    void shouldReturn400OnMissingJourneyStep() throws Exception {
        var input =
                JourneyRequest.builder().ipAddress(TEST_IP).ipvSessionId(TEST_SESSION_ID).build();

        Map<String, Object> output =
                getProcessJourneyStepHandler(StateMachineInitializerMode.TEST)
                        .handleRequest(input, mockContext);

        assertEquals(HttpStatusCode.BAD_REQUEST, output.get(STATUS_CODE));
        assertEquals(ErrorResponse.MISSING_JOURNEY_EVENT.getCode(), output.get(CODE));
        assertEquals(ErrorResponse.MISSING_JOURNEY_EVENT.getMessage(), output.get(MESSAGE));
    }

    @Test
    void shouldReturn400OnMissingSessionIdParam() throws Exception {
        var input = JourneyRequest.builder().ipAddress(TEST_IP).journey(JOURNEY_NEXT).build();

        Map<String, Object> output =
                getProcessJourneyStepHandler().handleRequest(input, mockContext);

        assertEquals(HttpStatusCode.BAD_REQUEST, output.get(STATUS_CODE));
        assertEquals(ErrorResponse.MISSING_IPV_SESSION_ID.getCode(), output.get(CODE));
        assertEquals(ErrorResponse.MISSING_IPV_SESSION_ID.getMessage(), output.get(MESSAGE));
    }

    @Test
    void shouldReturn400WhenInvalidSessionIdProvided() throws Exception {
        var input =
                JourneyRequest.builder()
                        .ipAddress(TEST_IP)
                        .journey(JOURNEY_NEXT)
                        .ipvSessionId(TEST_SESSION_ID)
                        .build();
        when(mockIpvSessionService.getIpvSession(anyString()))
                .thenThrow(new IpvSessionNotFoundException("Not found"));

        Map<String, Object> output =
                getProcessJourneyStepHandler().handleRequest(input, mockContext);

        assertEquals(HttpStatusCode.BAD_REQUEST, output.get(STATUS_CODE));
        assertEquals(ErrorResponse.IPV_SESSION_NOT_FOUND.getCode(), output.get(CODE));
        assertEquals(ErrorResponse.IPV_SESSION_NOT_FOUND.getMessage(), output.get(MESSAGE));
    }

    @Test
    void shouldReturn500WhenUnknownJourneyEngineStepProvided() throws Exception {
        var input =
                JourneyRequest.builder()
                        .ipAddress(TEST_IP)
                        .journey("invalid-event")
                        .ipvSessionId(TEST_SESSION_ID)
                        .build();

        mockIpvSessionItemAndTimeout("START");

        Map<String, Object> output =
                getProcessJourneyStepHandler().handleRequest(input, mockContext);

        assertEquals(HttpStatusCode.INTERNAL_SERVER_ERROR, output.get(STATUS_CODE));
        assertEquals(ErrorResponse.FAILED_JOURNEY_ENGINE_STEP.getCode(), output.get(CODE));
        assertEquals(ErrorResponse.FAILED_JOURNEY_ENGINE_STEP.getMessage(), output.get(MESSAGE));
    }

    @Test
    void shouldReturn500WhenUserIsInUnknownState() throws Exception {
        var input =
                JourneyRequest.builder()
                        .ipAddress(TEST_IP)
                        .journey(JOURNEY_NEXT)
                        .ipvSessionId(TEST_SESSION_ID)
                        .build();

        mockIpvSessionItemAndTimeout("INVALIDSTATE");

        Map<String, Object> output =
                getProcessJourneyStepHandler().handleRequest(input, mockContext);

        assertEquals(HttpStatusCode.INTERNAL_SERVER_ERROR, output.get(STATUS_CODE));
        assertEquals(ErrorResponse.FAILED_JOURNEY_ENGINE_STEP.getCode(), output.get(CODE));
        assertEquals(ErrorResponse.FAILED_JOURNEY_ENGINE_STEP.getMessage(), output.get(MESSAGE));
    }

    @Test
    void shouldReturn500IfNoStateMachineMatchingJourneyType() throws Exception {
        var input =
                JourneyRequest.builder()
                        .ipAddress(TEST_IP)
                        .journey(JOURNEY_NEXT)
                        .ipvSessionId(TEST_SESSION_ID)
                        .build();

        mockIpvSessionItemAndTimeout("START");

        ProcessJourneyEventHandler processJourneyEventHandler =
                new ProcessJourneyEventHandler(
                        mockAuditService,
                        mockIpvSessionService,
                        mockConfigService,
                        mockClientOAuthSessionService,
                        List.of(),
                        StateMachineInitializerMode.STANDARD,
                        REAL_NESTED_JOURNEY_TYPES,
                        mockCimitUtilityService);

        Map<String, Object> output = processJourneyEventHandler.handleRequest(input, mockContext);

        assertEquals(HttpStatusCode.INTERNAL_SERVER_ERROR, output.get(STATUS_CODE));
        assertEquals(ErrorResponse.FAILED_JOURNEY_ENGINE_STEP.getCode(), output.get(CODE));
        assertEquals(ErrorResponse.FAILED_JOURNEY_ENGINE_STEP.getMessage(), output.get(MESSAGE));
    }

    @Test
    void shouldReturnResponseForBuildClientOAuthResponseEvent() throws Exception {
        var input =
                JourneyRequest.builder()
                        .ipAddress(TEST_IP)
                        .journey(JOURNEY_BUILD_CLIENT_OAUTH_RESPONSE)
                        .ipvSessionId(null)
                        .build();

        Map<String, Object> output =
                getProcessJourneyStepHandler().handleRequest(input, mockContext);

        assertEquals(JOURNEY_BUILD_CLIENT_OAUTH_RESPONSE, output.get("journey"));
    }

    @Test
    void shouldReturnCurrentStateIfPageOutOfSync() throws Exception {
        var input =
                JourneyRequest.builder()
                        .ipAddress(TEST_IP)
                        .journey(JOURNEY_EVENT_ONE_WITH_TEST_CURRENT_PAGE)
                        .ipvSessionId(TEST_SESSION_ID)
                        .build();

        mockIpvSessionItemAndTimeout("PAGE_STATE");

        ProcessJourneyEventHandler processJourneyEventHandler =
                new ProcessJourneyEventHandler(
                        mockAuditService,
                        mockIpvSessionService,
                        mockConfigService,
                        mockClientOAuthSessionService,
                        List.of(INITIAL_JOURNEY_SELECTION, TECHNICAL_ERROR),
                        StateMachineInitializerMode.TEST,
                        TEST_NESTED_JOURNEY_TYPES,
                        mockCimitUtilityService);

        Map<String, Object> output = processJourneyEventHandler.handleRequest(input, mockContext);

        assertEquals("page-id-for-page-state", output.get("page"));
    }

    @Test
    void shouldReturnNextStateIfInSync() throws Exception {
        var input =
                JourneyRequest.builder()
                        .ipAddress(TEST_IP)
                        .journey(JOURNEY_EVENT_TWO_WITH_CORRECT_CURRENT_PAGE)
                        .ipvSessionId(TEST_SESSION_ID)
                        .build();

        when(mockConfigService.isCredentialIssuerEnabled("aCriId")).thenReturn(true);

        mockIpvSessionItemAndTimeout("PAGE_STATE");

        ProcessJourneyEventHandler processJourneyEventHandler =
                new ProcessJourneyEventHandler(
                        mockAuditService,
                        mockIpvSessionService,
                        mockConfigService,
                        mockClientOAuthSessionService,
                        List.of(INITIAL_JOURNEY_SELECTION, TECHNICAL_ERROR),
                        StateMachineInitializerMode.TEST,
                        TEST_NESTED_JOURNEY_TYPES,
                        mockCimitUtilityService);

        Map<String, Object> output = processJourneyEventHandler.handleRequest(input, mockContext);

        assertEquals("/journey/cri/build-oauth-request/aCriId", output.get("journey"));
    }

    @ParameterizedTest()
    @MethodSource("journeyUrisWithCurrentPageForCri")
    void shouldTransitionCriStateIfCurrentPageMatchesCriId(
            String journeyUri, String expectedNewJourneyState) throws Exception {
        var input =
                JourneyRequest.builder()
                        .ipAddress(TEST_IP)
                        .journey(journeyUri)
                        .ipvSessionId(TEST_SESSION_ID)
                        .build();

        mockIpvSessionItemAndTimeout("CRI_STATE");

        ProcessJourneyEventHandler processJourneyEventHandler =
                new ProcessJourneyEventHandler(
                        mockAuditService,
                        mockIpvSessionService,
                        mockConfigService,
                        mockClientOAuthSessionService,
                        List.of(INITIAL_JOURNEY_SELECTION, TECHNICAL_ERROR),
                        StateMachineInitializerMode.TEST,
                        TEST_NESTED_JOURNEY_TYPES,
                        mockCimitUtilityService);

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
    void shouldThrowErrorIfJourneyEventDuringProcess() throws Exception {
        var input =
                JourneyRequest.builder()
                        .ipAddress(TEST_IP)
                        .journey(JOURNEY_EVENT_ONE_WITH_TEST_CURRENT_PAGE)
                        .ipvSessionId(TEST_SESSION_ID)
                        .build();

        mockIpvSessionItemAndTimeout("PROCESS_STATE");

        ProcessJourneyEventHandler processJourneyEventHandler =
                new ProcessJourneyEventHandler(
                        mockAuditService,
                        mockIpvSessionService,
                        mockConfigService,
                        mockClientOAuthSessionService,
                        List.of(INITIAL_JOURNEY_SELECTION, TECHNICAL_ERROR),
                        StateMachineInitializerMode.TEST,
                        TEST_NESTED_JOURNEY_TYPES,
                        mockCimitUtilityService);

        Map<String, Object> output = processJourneyEventHandler.handleRequest(input, mockContext);

        assertEquals(HttpStatusCode.INTERNAL_SERVER_ERROR, output.get(STATUS_CODE));
        assertEquals(ErrorResponse.FAILED_JOURNEY_ENGINE_STEP.getCode(), output.get(CODE));
        assertEquals(ErrorResponse.FAILED_JOURNEY_ENGINE_STEP.getMessage(), output.get(MESSAGE));
    }

    @Test
    void shouldReturnErrorPageIfSessionHasExpired() throws Exception {
        var input =
                JourneyRequest.builder()
                        .ipAddress(TEST_IP)
                        .journey(JOURNEY_NEXT)
                        .ipvSessionId(TEST_SESSION_ID)
                        .build();

        mockIpvSessionItemAndTimeout("CRI_STATE");
        IpvSessionItem ipvSessionItem = mockIpvSessionService.getIpvSession(TEST_IP);
        ipvSessionItem.setCreationDateTime(Instant.now().minusSeconds(100).toString());
        when(mockIpvSessionService.checkIfSessionExpired(ipvSessionItem)).thenReturn(true);

        Map<String, Object> output =
                getProcessJourneyStepHandler().handleRequest(input, mockContext);

        ArgumentCaptor<IpvSessionItem> sessionArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(mockIpvSessionService).updateIpvSession(sessionArgumentCaptor.capture());

        IpvSessionItem capturedIpvSessionItem = sessionArgumentCaptor.getValue();
        assertEquals(
                new JourneyState(SESSION_TIMEOUT, TIMEOUT_UNRECOVERABLE_STATE),
                capturedIpvSessionItem.getState());
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
        assertEquals(TEST_USER_ID, capturedAuditEvent.getUser().getUserId());
        assertEquals("testjourneyid", capturedAuditEvent.getUser().getGovukSigninJourneyId());
    }

    @Test
    void shouldClearOauthSessionIfItExists() throws Exception {
        var input =
                JourneyRequest.builder()
                        .ipAddress(TEST_IP)
                        .journey(JOURNEY_NEXT)
                        .ipvSessionId(TEST_SESSION_ID)
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
                        .ipvSessionId(TEST_SESSION_ID)
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
                        "testWithEvidenceRequest",
                        "/journey/cri/build-oauth-request/aCriId?evidenceRequest=eyJzY29yaW5nUG9saWN5IjoiZ3BnNDUiLCJzdHJlbmd0aFNjb3JlIjoyfQ%3D%3D"),
                Arguments.of(
                        "testWithContextAndEvidenceRequest",
                        "/journey/cri/build-oauth-request/aCriId?context=test_context&evidenceRequest=eyJzY29yaW5nUG9saWN5IjoiZ3BnNDUiLCJzdHJlbmd0aFNjb3JlIjoyfQ%3D%3D"));
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
                mockIpvSessionService.getIpvSession(TEST_SESSION_ID).getState().subJourney());

        verify(mockAuditService).sendAuditEvent(auditEventCaptor.capture());
        var capturedAuditEvent = auditEventCaptor.getValue();

        assertEquals(AuditEventTypes.IPV_SUBJOURNEY_START, capturedAuditEvent.getEventName());
        assertEquals(
                IpvJourneyTypes.TECHNICAL_ERROR,
                ((AuditExtensionSubjourneyType) capturedAuditEvent.getExtensions()).journeyType());
        assertEquals("core", capturedAuditEvent.getComponentId());
        assertEquals(TEST_USER_ID, capturedAuditEvent.getUser().getUserId());
        assertEquals("testjourneyid", capturedAuditEvent.getUser().getGovukSigninJourneyId());
    }

    @Test
    void shouldSendAuditEventWhenThereIsAuditEventInJourneyMap() throws Exception {
        var input =
                JourneyRequest.builder()
                        .ipAddress(TEST_IP)
                        .journey("testWithAuditEvent")
                        .ipvSessionId(TEST_SESSION_ID)
                        .build();
        mockIpvSessionItemAndTimeout("CRI_STATE");

        getProcessJourneyStepHandler(StateMachineInitializerMode.TEST)
                .handleRequest(input, mockContext);

        verify(mockAuditService).sendAuditEvent(auditEventCaptor.capture());
        AuditEvent capturedAuditEvent = auditEventCaptor.getValue();

        assertEquals(IPV_NO_PHOTO_ID_JOURNEY_START, capturedAuditEvent.getEventName());
        assertEquals("core", capturedAuditEvent.getComponentId());
        assertEquals(TEST_USER_ID, capturedAuditEvent.getUser().getUserId());
        assertEquals("testjourneyid", capturedAuditEvent.getUser().getGovukSigninJourneyId());
    }

    @Test
    void shouldSendMultipleAuditEventsWithContext() throws Exception {
        var input =
                JourneyRequest.builder()
                        .ipAddress(TEST_IP)
                        .journey("testWithAuditEventContext")
                        .ipvSessionId(TEST_SESSION_ID)
                        .build();
        mockIpvSessionItemAndTimeout("CRI_STATE");

        getProcessJourneyStepHandler(StateMachineInitializerMode.TEST)
                .handleRequest(input, mockContext);

        verify(mockAuditService, times(4)).sendAuditEvent(auditEventCaptor.capture());
        var capturedAuditEvents = auditEventCaptor.getAllValues();
        assertEquals(4, capturedAuditEvents.size());

        var firstEvent = capturedAuditEvents.get(0);
        assertEquals(IPV_NO_PHOTO_ID_JOURNEY_START, firstEvent.getEventName());
        assertEquals("core", firstEvent.getComponentId());
        assertEquals(TEST_USER_ID, firstEvent.getUser().getUserId());
        assertEquals("testjourneyid", firstEvent.getUser().getGovukSigninJourneyId());

        var secondEvent = capturedAuditEvents.get(1);
        assertEquals(AuditEventTypes.IPV_MITIGATION_START, secondEvent.getEventName());
        assertEquals("core", secondEvent.getComponentId());
        assertEquals(TEST_USER_ID, secondEvent.getUser().getUserId());
        assertEquals("testjourneyid", secondEvent.getUser().getGovukSigninJourneyId());
        assertEquals(
                new AuditExtensionMitigationType("test-mitigation"), secondEvent.getExtensions());

        var thirdEvent = capturedAuditEvents.get(2);
        assertEquals(AuditEventTypes.IPV_USER_DETAILS_UPDATE_SELECTED, thirdEvent.getEventName());
        assertEquals("core", thirdEvent.getComponentId());
        assertEquals(TEST_USER_ID, thirdEvent.getUser().getUserId());
        assertEquals("testjourneyid", thirdEvent.getUser().getGovukSigninJourneyId());
        assertEquals(
                new AuditExtensionUserDetailsUpdateSelected(List.of("address"), true),
                thirdEvent.getExtensions());

        var fourthEvent = capturedAuditEvents.get(3);
        assertEquals(AuditEventTypes.IPV_USER_DETAILS_UPDATE_END, fourthEvent.getEventName());
        assertEquals("core", fourthEvent.getComponentId());
        assertEquals(TEST_USER_ID, fourthEvent.getUser().getUserId());
        assertEquals("testjourneyid", fourthEvent.getUser().getGovukSigninJourneyId());
        assertEquals(new AuditExtensionSuccessful(false), fourthEvent.getExtensions());
    }

    @Test
    void shouldUpdateStateStackWithJourneyAndStateWhenStartingNewSubjourney() throws Exception {
        var input =
                JourneyRequest.builder()
                        .ipAddress(TEST_IP)
                        .journey("testJourneyStep")
                        .ipvSessionId(TEST_SESSION_ID)
                        .build();

        mockIpvSessionItemAndTimeout("CRI_STATE");

        ProcessJourneyEventHandler processJourneyEventHandler =
                new ProcessJourneyEventHandler(
                        mockAuditService,
                        mockIpvSessionService,
                        mockConfigService,
                        mockClientOAuthSessionService,
                        List.of(INITIAL_JOURNEY_SELECTION, TECHNICAL_ERROR),
                        StateMachineInitializerMode.TEST,
                        TEST_NESTED_JOURNEY_TYPES,
                        mockCimitUtilityService);

        processJourneyEventHandler.handleRequest(input, mockContext);

        assertEquals(
                new JourneyState(TECHNICAL_ERROR, "TECHNICAL_ERROR_PAGE"),
                mockIpvSessionService.getIpvSession("anyString").getState());
    }

    @Test
    void shouldUpdateStateStackWhenTransitioningWithinSubjourney() throws Exception {
        var input =
                JourneyRequest.builder()
                        .ipAddress(TEST_IP)
                        .journey("eventOne")
                        .ipvSessionId(TEST_SESSION_ID)
                        .build();

        mockIpvSessionItemAndTimeout("PAGE_STATE");

        ProcessJourneyEventHandler processJourneyEventHandler =
                new ProcessJourneyEventHandler(
                        mockAuditService,
                        mockIpvSessionService,
                        mockConfigService,
                        mockClientOAuthSessionService,
                        List.of(INITIAL_JOURNEY_SELECTION),
                        StateMachineInitializerMode.TEST,
                        TEST_NESTED_JOURNEY_TYPES,
                        mockCimitUtilityService);

        processJourneyEventHandler.handleRequest(input, mockContext);

        assertEquals(
                new JourneyState(INITIAL_JOURNEY_SELECTION, "ANOTHER_PAGE_STATE"),
                mockIpvSessionService.getIpvSession("anyString").getState());
    }

    @Test
    @Tag(SKIP_CHECK_AUDIT_EVENT_WAIT_TAG)
    void shouldGoBackIfCurrentAndPreviousStatesArePages() throws Exception {
        var firstTransitionInput =
                JourneyRequest.builder()
                        .ipAddress(TEST_IP)
                        .journey("eventFour")
                        .ipvSessionId(TEST_SESSION_ID)
                        .build();

        var secondTransitionInput =
                JourneyRequest.builder()
                        .ipAddress(TEST_IP)
                        .journey("anotherPageState")
                        .ipvSessionId(TEST_SESSION_ID)
                        .build();

        var backInput =
                JourneyRequest.builder()
                        .ipAddress(TEST_IP)
                        .journey("back")
                        .ipvSessionId(TEST_SESSION_ID)
                        .build();

        mockIpvSessionItemAndTimeout("PAGE_STATE");
        var ipvSessionItem = mockIpvSessionService.getIpvSession("anyString");

        ProcessJourneyEventHandler processJourneyEventHandler =
                new ProcessJourneyEventHandler(
                        mockAuditService,
                        mockIpvSessionService,
                        mockConfigService,
                        mockClientOAuthSessionService,
                        List.of(INITIAL_JOURNEY_SELECTION),
                        StateMachineInitializerMode.TEST,
                        TEST_NESTED_JOURNEY_TYPES,
                        mockCimitUtilityService);

        InOrder inOrder = inOrder(ipvSessionItem, mockIpvSessionService);

        processJourneyEventHandler.handleRequest(firstTransitionInput, mockContext);
        inOrder.verify(ipvSessionItem)
                .pushState(
                        new JourneyState(
                                INITIAL_JOURNEY_SELECTION, "PAGE_STATE_AT_START_OF_NO_PHOTO_ID"));
        inOrder.verify(mockIpvSessionService).updateIpvSession(ipvSessionItem);
        assertEquals(
                new JourneyState(INITIAL_JOURNEY_SELECTION, "PAGE_STATE_AT_START_OF_NO_PHOTO_ID"),
                ipvSessionItem.getState());

        processJourneyEventHandler.handleRequest(secondTransitionInput, mockContext);
        inOrder.verify(ipvSessionItem)
                .pushState(new JourneyState(INITIAL_JOURNEY_SELECTION, "ANOTHER_PAGE_STATE"));
        inOrder.verify(mockIpvSessionService).updateIpvSession(ipvSessionItem);
        assertEquals(
                new JourneyState(INITIAL_JOURNEY_SELECTION, "ANOTHER_PAGE_STATE"),
                ipvSessionItem.getState());

        processJourneyEventHandler.handleRequest(backInput, mockContext);
        inOrder.verify(ipvSessionItem).popState();
        inOrder.verify(mockIpvSessionService).updateIpvSession(ipvSessionItem);
        assertEquals(
                new JourneyState(INITIAL_JOURNEY_SELECTION, "PAGE_STATE_AT_START_OF_NO_PHOTO_ID"),
                ipvSessionItem.getState());

        processJourneyEventHandler.handleRequest(backInput, mockContext);
        inOrder.verify(ipvSessionItem).popState();
        inOrder.verify(mockIpvSessionService).updateIpvSession(ipvSessionItem);
        assertEquals(
                new JourneyState(INITIAL_JOURNEY_SELECTION, "PAGE_STATE"),
                ipvSessionItem.getState());
    }

    @Test
    @Tag(SKIP_CHECK_AUDIT_EVENT_WAIT_TAG)
    void shouldGoBackIfStatesAreInSeparateJourneyMaps() throws Exception {
        var inputToNextPageState =
                JourneyRequest.builder()
                        .ipAddress(TEST_IP)
                        .journey("eventThree")
                        .ipvSessionId(TEST_SESSION_ID)
                        .build();

        var backInput =
                JourneyRequest.builder()
                        .ipAddress(TEST_IP)
                        .journey("back")
                        .ipvSessionId(TEST_SESSION_ID)
                        .build();

        mockIpvSessionItemAndTimeout("PAGE_STATE");
        var ipvSession = mockIpvSessionService.getIpvSession("anyString");

        ProcessJourneyEventHandler processJourneyEventHandler =
                new ProcessJourneyEventHandler(
                        mockAuditService,
                        mockIpvSessionService,
                        mockConfigService,
                        mockClientOAuthSessionService,
                        List.of(INITIAL_JOURNEY_SELECTION, TECHNICAL_ERROR),
                        StateMachineInitializerMode.TEST,
                        TEST_NESTED_JOURNEY_TYPES,
                        mockCimitUtilityService);

        var nextResponse =
                processJourneyEventHandler.handleRequest(inputToNextPageState, mockContext);
        assertEquals("technical-error-page", nextResponse.get("page"));
        assertEquals(
                new JourneyState(TECHNICAL_ERROR, "TECHNICAL_ERROR_PAGE"), ipvSession.getState());

        InOrder auditInOrderOne = inOrder(mockAuditService);
        auditInOrderOne.verify(mockAuditService).awaitAuditEvents();
        auditInOrderOne.verifyNoMoreInteractions();
        reset(mockAuditService);

        var backResponse = processJourneyEventHandler.handleRequest(backInput, mockContext);
        assertEquals("page-id-for-page-state", backResponse.get("page"));
        assertEquals(
                new JourneyState(INITIAL_JOURNEY_SELECTION, "PAGE_STATE"), ipvSession.getState());

        InOrder auditInOrderTwo = inOrder(mockAuditService);
        auditInOrderTwo.verify(mockAuditService).awaitAuditEvents();
        auditInOrderTwo.verifyNoMoreInteractions();
    }

    @Test
    @Tag(SKIP_CHECK_AUDIT_EVENT_WAIT_TAG)
    void shouldGoBackIfCurrentPageIsNestedStateAndPreviousIsNot() throws Exception {
        var inputToEnterNestedStates =
                JourneyRequest.builder()
                        .ipAddress(TEST_IP)
                        .journey("enterNestedJourneyAtStateOne")
                        .ipvSessionId(TEST_SESSION_ID)
                        .build();

        var backInput =
                JourneyRequest.builder()
                        .ipAddress(TEST_IP)
                        .journey("back")
                        .ipvSessionId(TEST_SESSION_ID)
                        .build();

        mockIpvSessionItemAndTimeout("PAGE_STATE_AT_START_OF_NO_PHOTO_ID");
        var ipvSession = mockIpvSessionService.getIpvSession("anyString");

        ProcessJourneyEventHandler processJourneyEventHandler =
                new ProcessJourneyEventHandler(
                        mockAuditService,
                        mockIpvSessionService,
                        mockConfigService,
                        mockClientOAuthSessionService,
                        List.of(INITIAL_JOURNEY_SELECTION, TECHNICAL_ERROR),
                        StateMachineInitializerMode.TEST,
                        TEST_NESTED_JOURNEY_TYPES,
                        mockCimitUtilityService);

        var nextResponse =
                processJourneyEventHandler.handleRequest(inputToEnterNestedStates, mockContext);
        assertEquals("page-id-nested-state-one", nextResponse.get("page"));
        assertEquals(
                new JourneyState(
                        INITIAL_JOURNEY_SELECTION, "NESTED_JOURNEY_INVOKE_STATE/NESTED_STATE_ONE"),
                ipvSession.getState());

        InOrder auditInOrderOne = inOrder(mockAuditService);
        auditInOrderOne.verify(mockAuditService).awaitAuditEvents();
        auditInOrderOne.verifyNoMoreInteractions();
        reset(mockAuditService);

        var backResponse = processJourneyEventHandler.handleRequest(backInput, mockContext);
        assertEquals("page-id-for-page-state-at-start-of-no-photo-id", backResponse.get("page"));
        assertEquals(
                new JourneyState(INITIAL_JOURNEY_SELECTION, "PAGE_STATE_AT_START_OF_NO_PHOTO_ID"),
                ipvSession.getState());

        InOrder auditInOrderTwo = inOrder(mockAuditService);
        auditInOrderTwo.verify(mockAuditService).awaitAuditEvents();
        auditInOrderTwo.verifyNoMoreInteractions();
    }

    @Test
    @Tag(SKIP_CHECK_AUDIT_EVENT_WAIT_TAG)
    void shouldRecoredAuditEventWhenEnteringNestedJourney() throws Exception {
        // Arrange
        var inputToEnterNestedStates =
                JourneyRequest.builder()
                        .ipAddress(TEST_IP)
                        .journey("enterNestedJourneyAtStateOne")
                        .ipvSessionId(TEST_SESSION_ID)
                        .build();

        mockIpvSessionItemAndTimeout("PAGE_STATE_WITH_AUDIT_EVENT_ON_SUBJOURNEY");
        var ipvSession = mockIpvSessionService.getIpvSession("anyString");

        ProcessJourneyEventHandler processJourneyEventHandler =
                new ProcessJourneyEventHandler(
                        mockAuditService,
                        mockIpvSessionService,
                        mockConfigService,
                        mockClientOAuthSessionService,
                        List.of(INITIAL_JOURNEY_SELECTION, TECHNICAL_ERROR),
                        StateMachineInitializerMode.TEST,
                        TEST_NESTED_JOURNEY_TYPES,
                        mockCimitUtilityService);

        // Act
        var nextResponse =
                processJourneyEventHandler.handleRequest(inputToEnterNestedStates, mockContext);

        // Assert
        assertEquals("page-id-nested-state-one", nextResponse.get("page"));
        assertEquals(
                new JourneyState(
                        INITIAL_JOURNEY_SELECTION, "NESTED_JOURNEY_INVOKE_STATE/NESTED_STATE_ONE"),
                ipvSession.getState());

        InOrder auditInOrderOne = inOrder(mockAuditService);
        auditInOrderOne.verify(mockAuditService).sendAuditEvent(auditEventCaptor.capture());
        auditInOrderOne.verify(mockAuditService).awaitAuditEvents();
        auditInOrderOne.verifyNoMoreInteractions();

        var auditEvent = auditEventCaptor.getValue();
        assertEquals(IPV_NO_PHOTO_ID_JOURNEY_START, auditEvent.getEventName());
    }

    @Test
    @Tag(SKIP_CHECK_AUDIT_EVENT_WAIT_TAG)
    void shouldUseBackEventDefinedOnStateIfExists() throws Exception {
        var inputToNextPageState =
                JourneyRequest.builder()
                        .ipAddress(TEST_IP)
                        .journey("eventFive")
                        .ipvSessionId(TEST_SESSION_ID)
                        .build();

        var backInput =
                JourneyRequest.builder()
                        .ipAddress(TEST_IP)
                        .journey("back")
                        .ipvSessionId(TEST_SESSION_ID)
                        .build();

        mockIpvSessionItemAndTimeout("PAGE_STATE");
        var ipvSession = mockIpvSessionService.getIpvSession("anyString");

        ProcessJourneyEventHandler processJourneyEventHandler =
                new ProcessJourneyEventHandler(
                        mockAuditService,
                        mockIpvSessionService,
                        mockConfigService,
                        mockClientOAuthSessionService,
                        List.of(INITIAL_JOURNEY_SELECTION, TECHNICAL_ERROR),
                        StateMachineInitializerMode.TEST,
                        TEST_NESTED_JOURNEY_TYPES,
                        mockCimitUtilityService);

        var nextResponse =
                processJourneyEventHandler.handleRequest(inputToNextPageState, mockContext);
        assertEquals("page-id-for-page-state-with-back-event", nextResponse.get("page"));
        assertEquals(
                new JourneyState(INITIAL_JOURNEY_SELECTION, "PAGE_STATE_WITH_BACK_EVENT"),
                ipvSession.getState());

        InOrder auditInOrderOne = inOrder(mockAuditService);
        auditInOrderOne.verify(mockAuditService).awaitAuditEvents();
        auditInOrderOne.verifyNoMoreInteractions();
        reset(mockAuditService);

        processJourneyEventHandler.handleRequest(backInput, mockContext);
        assertEquals(
                new JourneyState(INITIAL_JOURNEY_SELECTION, "PROCESS_STATE"),
                ipvSession.getState());

        InOrder auditInOrderTwo = inOrder(mockAuditService);
        auditInOrderTwo.verify(mockAuditService).awaitAuditEvents();
        auditInOrderTwo.verifyNoMoreInteractions();
    }

    @Test
    void shouldReturn500IfPreviousStateNotPageState() throws Exception {
        var input =
                JourneyRequest.builder()
                        .ipAddress(TEST_IP)
                        .journey("back")
                        .ipvSessionId(TEST_SESSION_ID)
                        .build();

        mockIpvSessionItemAndTimeout("PAGE_STATE");
        IpvSessionItem ipvSession = mockIpvSessionService.getIpvSession("anyString");
        ipvSession.pushState(new JourneyState(INITIAL_JOURNEY_SELECTION, "CRI_STATE"));
        ipvSession.pushState(new JourneyState(INITIAL_JOURNEY_SELECTION, "PAGE_STATE"));

        ProcessJourneyEventHandler processJourneyEventHandler =
                new ProcessJourneyEventHandler(
                        mockAuditService,
                        mockIpvSessionService,
                        mockConfigService,
                        mockClientOAuthSessionService,
                        List.of(INITIAL_JOURNEY_SELECTION),
                        StateMachineInitializerMode.TEST,
                        TEST_NESTED_JOURNEY_TYPES,
                        mockCimitUtilityService);

        var response = processJourneyEventHandler.handleRequest(input, mockContext);

        assertEquals(HttpStatusCode.INTERNAL_SERVER_ERROR, response.get(STATUS_CODE));
        assertEquals(ErrorResponse.FAILED_JOURNEY_ENGINE_STEP.getCode(), response.get(CODE));
        assertEquals(ErrorResponse.FAILED_JOURNEY_ENGINE_STEP.getMessage(), response.get(MESSAGE));
    }

    @Test
    @Tag(SKIP_CHECK_AUDIT_EVENT_WAIT_TAG)
    void shouldGoBackIfPreviousStateIsIdentifyDeviceState() throws Exception {
        var firstTransitionInput =
                JourneyRequest.builder()
                        .ipAddress(TEST_IP)
                        .journey("eventEight")
                        .ipvSessionId(TEST_SESSION_ID)
                        .build();

        var secondTransitionInput =
                JourneyRequest.builder()
                        .ipAddress(TEST_IP)
                        .journey("eventOne")
                        .ipvSessionId(TEST_SESSION_ID)
                        .build();

        var backInput =
                JourneyRequest.builder()
                        .ipAddress(TEST_IP)
                        .journey("back")
                        .ipvSessionId(TEST_SESSION_ID)
                        .build();

        mockIpvSessionItemAndTimeout("PAGE_STATE");
        var ipvSessionItem = mockIpvSessionService.getIpvSession("anyString");

        ProcessJourneyEventHandler processJourneyEventHandler =
                new ProcessJourneyEventHandler(
                        mockAuditService,
                        mockIpvSessionService,
                        mockConfigService,
                        mockClientOAuthSessionService,
                        List.of(INITIAL_JOURNEY_SELECTION),
                        StateMachineInitializerMode.TEST,
                        TEST_NESTED_JOURNEY_TYPES,
                        mockCimitUtilityService);

        processJourneyEventHandler.handleRequest(firstTransitionInput, mockContext);
        assertEquals(
                new JourneyState(INITIAL_JOURNEY_SELECTION, "STRATEGIC_APP_TRIAGE/IDENTIFY_DEVICE"),
                ipvSessionItem.getState());

        processJourneyEventHandler.handleRequest(secondTransitionInput, mockContext);
        assertEquals(
                new JourneyState(
                        INITIAL_JOURNEY_SELECTION, "STRATEGIC_APP_TRIAGE/NESTED_STATE_TWO"),
                ipvSessionItem.getState());

        processJourneyEventHandler.handleRequest(backInput, mockContext);
        assertEquals(
                new JourneyState(INITIAL_JOURNEY_SELECTION, "PAGE_STATE"),
                ipvSessionItem.getState());
    }

    @Test
    void shouldReturn500IfStateMachineNotFoundWhenCheckingPageState() throws Exception {
        var input =
                JourneyRequest.builder()
                        .ipAddress(TEST_IP)
                        .journey("back")
                        .ipvSessionId(TEST_SESSION_ID)
                        .build();

        mockIpvSessionItemAndTimeout("PAGE_STATE");
        IpvSessionItem ipvSession = mockIpvSessionService.getIpvSession("anyString");
        ipvSession.pushState(new JourneyState(TECHNICAL_ERROR, "CRI_STATE"));
        ipvSession.pushState(new JourneyState(INITIAL_JOURNEY_SELECTION, "PAGE_STATE"));

        ProcessJourneyEventHandler processJourneyEventHandler =
                new ProcessJourneyEventHandler(
                        mockAuditService,
                        mockIpvSessionService,
                        mockConfigService,
                        mockClientOAuthSessionService,
                        List.of(INITIAL_JOURNEY_SELECTION),
                        StateMachineInitializerMode.TEST,
                        TEST_NESTED_JOURNEY_TYPES,
                        mockCimitUtilityService);

        var response = processJourneyEventHandler.handleRequest(input, mockContext);

        assertEquals(HttpStatusCode.INTERNAL_SERVER_ERROR, response.get(STATUS_CODE));
        assertEquals(ErrorResponse.FAILED_JOURNEY_ENGINE_STEP.getCode(), response.get(CODE));
        assertEquals(ErrorResponse.FAILED_JOURNEY_ENGINE_STEP.getMessage(), response.get(MESSAGE));
    }

    @Test
    void shouldReturnMitigationStateIfCheckMitigationIsConfigured() throws Exception {
        var input =
                JourneyRequest.builder()
                        .ipAddress(TEST_IP)
                        .journey("eventWithMitigation")
                        .ipvSessionId(TEST_SESSION_ID)
                        .build();

        mockIpvSessionItemAndTimeout("PAGE_STATE");
        when(mockCimitUtilityService.getMitigationEventIfBreachingOrActive(any(), any(), any()))
                .thenReturn(Optional.of("first-mitigation"));

        var processJourneyEventHandler =
                getProcessJourneyStepHandler(StateMachineInitializerMode.TEST);

        var output = processJourneyEventHandler.handleRequest(input, mockContext);

        assertEquals("/journey/cri/build-oauth-request/aCriId", output.get("journey"));
    }

    @Test
    void shouldReturnMitigationStateFromNestedJourneyIfCheckMitigationIsConfigured()
            throws Exception {
        var input =
                JourneyRequest.builder()
                        .ipAddress(TEST_IP)
                        .journey("eventOne")
                        .ipvSessionId(TEST_SESSION_ID)
                        .build();

        mockIpvSessionItemAndTimeout("NESTED_JOURNEY_INVOKE_STATE/NESTED_STATE_ONE");
        when(mockCimitUtilityService.getMitigationEventIfBreachingOrActive(any(), any(), any()))
                .thenReturn(Optional.of("first-mitigation"));

        var processJourneyEventHandler =
                getProcessJourneyStepHandler(StateMachineInitializerMode.TEST);

        var output = processJourneyEventHandler.handleRequest(input, mockContext);

        assertEquals("page-id-for-page-state", output.get("page"));
    }

    private static Stream<Arguments> getMitigationEventIfBreachingOrActiveErrors() {
        return Stream.of(
                Arguments.of(new CredentialParseException("Unable to parse credentials")),
                Arguments.of(new CiExtractionException("Unable to extract CIs from VC")));
    }

    @ParameterizedTest
    @MethodSource("getMitigationEventIfBreachingOrActiveErrors")
    void shouldReturn500IfCimitUtilityServiceThrowsExceptionWhenGettingMitigations(
            Exception exception) throws Exception {
        var input =
                JourneyRequest.builder()
                        .ipAddress(TEST_IP)
                        .journey("eventWithMitigation")
                        .ipvSessionId(TEST_SESSION_ID)
                        .build();

        mockIpvSessionItemAndTimeout("PAGE_STATE");
        when(mockCimitUtilityService.getMitigationEventIfBreachingOrActive(any(), any(), any()))
                .thenThrow(exception);

        var processJourneyEventHandler =
                getProcessJourneyStepHandler(StateMachineInitializerMode.TEST);

        var response = processJourneyEventHandler.handleRequest(input, mockContext);

        assertEquals(HttpStatusCode.INTERNAL_SERVER_ERROR, response.get(STATUS_CODE));
        assertEquals(ErrorResponse.FAILED_JOURNEY_ENGINE_STEP.getCode(), response.get(CODE));
        assertEquals(ErrorResponse.FAILED_JOURNEY_ENGINE_STEP.getMessage(), response.get(MESSAGE));
    }

    @Test
    void shouldSetJourneyContextIfProvided() throws Exception {
        var input =
                JourneyRequest.builder()
                        .ipAddress(TEST_IP)
                        .journey("eventWithSetJourneyContext")
                        .ipvSessionId(TEST_SESSION_ID)
                        .build();

        var spyIpvSessionItem = mockIpvSessionItemAndTimeout("PAGE_STATE");

        var processJourneyEventHandler =
                getProcessJourneyStepHandler(StateMachineInitializerMode.TEST);

        var output = processJourneyEventHandler.handleRequest(input, mockContext);

        assertEquals("page-id-for-another-page-state", output.get("page"));
        verify(spyIpvSessionItem, times(1)).setJourneyContext("someContext");
        verify(mockIpvSessionService).updateIpvSession(spyIpvSessionItem);
    }

    @Test
    void shouldNotSetOrUnsetJourneyContextIfNotProvided() throws Exception {
        var input =
                JourneyRequest.builder()
                        .ipAddress(TEST_IP)
                        .journey("eventOne")
                        .ipvSessionId(TEST_SESSION_ID)
                        .build();

        var spyIpvSessionItem = mockIpvSessionItemAndTimeout("PAGE_STATE");

        var processJourneyEventHandler =
                getProcessJourneyStepHandler(StateMachineInitializerMode.TEST);

        var output = processJourneyEventHandler.handleRequest(input, mockContext);

        assertEquals("page-id-for-another-page-state", output.get("page"));
        verify(spyIpvSessionItem, times(0)).setJourneyContext("someContext");
        verify(spyIpvSessionItem, times(0)).unsetJourneyContext("someContext");
        verify(mockIpvSessionService).updateIpvSession(spyIpvSessionItem);
    }

    @Test
    void shouldUnsetJourneyContextIfProvided() throws Exception {
        var input =
                JourneyRequest.builder()
                        .ipAddress(TEST_IP)
                        .journey("eventWithUnsetJourneyContext")
                        .ipvSessionId(TEST_SESSION_ID)
                        .build();

        var spyIpvSessionItem = mockIpvSessionItemAndTimeout("PAGE_STATE");

        var processJourneyEventHandler =
                getProcessJourneyStepHandler(StateMachineInitializerMode.TEST);

        var output = processJourneyEventHandler.handleRequest(input, mockContext);

        assertEquals("page-id-for-another-page-state", output.get("page"));
        verify(spyIpvSessionItem, times(1)).unsetJourneyContext("someContext");
        verify(mockIpvSessionService).updateIpvSession(spyIpvSessionItem);
    }

    @Tag(SKIP_CHECK_AUDIT_EVENT_WAIT_TAG)
    @Test
    void shouldRouteToStateDependingOnJourneyContext() throws Exception {
        // The initial input sets the journey context and takes user to ANOTHER_PAGE_STATE state
        var initialInput =
                JourneyRequest.builder()
                        .ipAddress(TEST_IP)
                        .journey("eventWithSetJourneyContext")
                        .ipvSessionId(TEST_SESSION_ID)
                        .build();

        // Second input to test the journeyContext handling when on the ANOTHER_PAGE_STATE state
        var secondTransitionInput =
                JourneyRequest.builder()
                        .ipAddress(TEST_IP)
                        .journey("next")
                        .ipvSessionId(TEST_SESSION_ID)
                        .build();

        var processJourneyEventHandler =
                getProcessJourneyStepHandler(StateMachineInitializerMode.TEST);

        var spyIpvSessionItem = mockIpvSessionItemAndTimeout("PAGE_STATE");

        InOrder inOrder = inOrder(spyIpvSessionItem, mockIpvSessionService);

        // Act/Assert
        // Initial transition
        var initialOutput = processJourneyEventHandler.handleRequest(initialInput, mockContext);
        inOrder.verify(spyIpvSessionItem)
                .pushState(new JourneyState(INITIAL_JOURNEY_SELECTION, "PAGE_STATE"));
        inOrder.verify(spyIpvSessionItem, times(1)).setJourneyContext("someContext");
        inOrder.verify(spyIpvSessionItem)
                .pushState(new JourneyState(INITIAL_JOURNEY_SELECTION, "ANOTHER_PAGE_STATE"));
        inOrder.verify(mockIpvSessionService).updateIpvSession(spyIpvSessionItem);
        assertEquals("page-id-for-another-page-state", initialOutput.get("page"));

        // Second transition
        var secondOutput =
                processJourneyEventHandler.handleRequest(secondTransitionInput, mockContext);
        inOrder.verify(spyIpvSessionItem)
                .pushState(new JourneyState(INITIAL_JOURNEY_SELECTION, "CRI_STATE"));
        inOrder.verify(mockIpvSessionService).updateIpvSession(spyIpvSessionItem);
        assertEquals("/journey/cri/build-oauth-request/aCriId", secondOutput.get("journey"));
    }

    @Tag(SKIP_CHECK_AUDIT_EVENT_WAIT_TAG)
    @Test
    void shouldRouteToCorrectStateIfJourneyContextIsUnset() throws Exception {
        var spyIpvSessionItem = mockIpvSessionItemAndTimeout("PAGE_STATE");
        spyIpvSessionItem.setJourneyContext("someContext");

        // The initial input sets the journey context and takes user to ANOTHER_PAGE_STATE state
        var initialInput =
                JourneyRequest.builder()
                        .ipAddress(TEST_IP)
                        .journey("eventWithUnsetJourneyContext")
                        .ipvSessionId(TEST_SESSION_ID)
                        .build();

        // Second input to test the journeyContext handling when on the ANOTHER_PAGE_STATE state
        var secondTransitionInput =
                JourneyRequest.builder()
                        .ipAddress(TEST_IP)
                        .journey("next")
                        .ipvSessionId(TEST_SESSION_ID)
                        .build();

        var processJourneyEventHandler =
                getProcessJourneyStepHandler(StateMachineInitializerMode.TEST);

        InOrder inOrder = inOrder(spyIpvSessionItem, mockIpvSessionService);

        // Act/Assert
        // Initial transition
        var initialOutput = processJourneyEventHandler.handleRequest(initialInput, mockContext);
        inOrder.verify(spyIpvSessionItem)
                .pushState(new JourneyState(INITIAL_JOURNEY_SELECTION, "PAGE_STATE"));
        inOrder.verify(spyIpvSessionItem, times(1)).unsetJourneyContext("someContext");
        inOrder.verify(spyIpvSessionItem)
                .pushState(new JourneyState(INITIAL_JOURNEY_SELECTION, "ANOTHER_PAGE_STATE"));
        inOrder.verify(mockIpvSessionService).updateIpvSession(spyIpvSessionItem);
        assertEquals("page-id-for-another-page-state", initialOutput.get("page"));

        // Second transition
        var secondOutput =
                processJourneyEventHandler.handleRequest(secondTransitionInput, mockContext);
        inOrder.verify(spyIpvSessionItem)
                .pushState(new JourneyState(INITIAL_JOURNEY_SELECTION, "PROCESS_STATE"));
        inOrder.verify(mockIpvSessionService).updateIpvSession(spyIpvSessionItem);
        assertEquals("/journey/a-lambda-to-invoke", secondOutput.get("journey"));
    }

    @Test
    void shouldLogRuntimeExceptionsAndRethrow() throws Exception {
        // Arrange
        when(mockIpvSessionService.getIpvSession(anyString()))
                .thenThrow(new RuntimeException("Test error"));
        var input =
                JourneyRequest.builder()
                        .ipAddress(TEST_IP)
                        .journey("eventFive")
                        .ipvSessionId(TEST_SESSION_ID)
                        .build();

        ProcessJourneyEventHandler processJourneyEventHandler =
                new ProcessJourneyEventHandler(
                        mockAuditService,
                        mockIpvSessionService,
                        mockConfigService,
                        mockClientOAuthSessionService,
                        List.of(INITIAL_JOURNEY_SELECTION, TECHNICAL_ERROR),
                        StateMachineInitializerMode.TEST,
                        TEST_NESTED_JOURNEY_TYPES,
                        mockCimitUtilityService);

        var logCollector = LogCollector.getLogCollectorFor(ProcessJourneyEventHandler.class);

        // Act
        var thrown =
                assertThrows(
                        Exception.class,
                        () -> processJourneyEventHandler.handleRequest(input, mockContext),
                        "Expected handleRequest() to throw, but it didn't");

        // Assert
        assertEquals("Test error", thrown.getMessage());
        var logMessage = logCollector.getLogMessages().get(0);
        assertThat(logMessage, containsString("Unhandled lambda exception"));
        assertThat(logMessage, containsString("Test error"));
    }

    private IpvSessionItem mockIpvSessionItemAndTimeout(String userState) throws Exception {
        IpvSessionItem ipvSessionItem = spy(IpvSessionItem.class);
        ipvSessionItem.setIpvSessionId(SecureTokenHelper.getInstance().generate());
        ipvSessionItem.setCreationDateTime(Instant.now().toString());
        ipvSessionItem.pushState(new JourneyState(INITIAL_JOURNEY_SELECTION, userState));
        ipvSessionItem.setClientOAuthSessionId(SecureTokenHelper.getInstance().generate());
        ipvSessionItem.setSecurityCheckCredential(SIGNED_CONTRA_INDICATOR_VC_1);

        when(mockConfigService.getComponentId()).thenReturn("core");
        when(mockIpvSessionService.checkIfSessionExpired(ipvSessionItem)).thenReturn(false);
        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);
        when(mockClientOAuthSessionService.getClientOAuthSession(any()))
                .thenReturn(getClientOAuthSessionItem());

        return ipvSessionItem;
    }

    private ClientOAuthSessionItem getClientOAuthSessionItem() {
        return ClientOAuthSessionItem.builder()
                .clientOAuthSessionId(SecureTokenHelper.getInstance().generate())
                .responseType("code")
                .state("teststate")
                .redirectUri("https://example.com/redirect")
                .govukSigninJourneyId("testjourneyid")
                .userId(TEST_USER_ID)
                .evcsAccessToken(TEST_EVCS_ACCESS_TOKEN)
                .vtr(List.of("P2"))
                .scope(ScopeConstants.OPENID)
                .build();
    }

    private ProcessJourneyEventHandler getProcessJourneyStepHandler(
            StateMachineInitializerMode stateMachineInitializerMode) throws IOException {

        var journeyTypes =
                stateMachineInitializerMode.equals(StateMachineInitializerMode.TEST)
                        ? List.of(INITIAL_JOURNEY_SELECTION, TECHNICAL_ERROR)
                        : List.of(IpvJourneyTypes.values());

        var nestedJourneyTypes =
                stateMachineInitializerMode.equals(StateMachineInitializerMode.TEST)
                        ? TEST_NESTED_JOURNEY_TYPES
                        : REAL_NESTED_JOURNEY_TYPES;

        return new ProcessJourneyEventHandler(
                mockAuditService,
                mockIpvSessionService,
                mockConfigService,
                mockClientOAuthSessionService,
                journeyTypes,
                stateMachineInitializerMode,
                nestedJourneyTypes,
                mockCimitUtilityService);
    }

    private ProcessJourneyEventHandler getProcessJourneyStepHandler() throws IOException {
        return getProcessJourneyStepHandler(StateMachineInitializerMode.STANDARD);
    }
}
