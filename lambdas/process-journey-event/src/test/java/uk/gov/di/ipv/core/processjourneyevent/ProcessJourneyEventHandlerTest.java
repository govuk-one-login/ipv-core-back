package uk.gov.di.ipv.core.processjourneyevent;

import com.amazonaws.services.lambda.runtime.Context;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import org.apache.http.HttpStatus;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.auditing.AuditEvent;
import uk.gov.di.ipv.core.library.auditing.AuditEventTypes;
import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.helpers.SecureTokenHelper;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.ClientOAuthSessionDetailsService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.StateMachineInitializerMode;
import uk.gov.di.ipv.core.processjourneyevent.utils.ProcessJourneyStepEvents;
import uk.gov.di.ipv.core.processjourneyevent.utils.ProcessJourneyStepStates;
import uk.org.webcompere.systemstubs.environment.EnvironmentVariables;
import uk.org.webcompere.systemstubs.jupiter.SystemStub;
import uk.org.webcompere.systemstubs.jupiter.SystemStubsExtension;

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
import static uk.gov.di.ipv.core.library.domain.IpvJourneyTypes.IPV_CORE_MAIN_JOURNEY;

@ExtendWith(MockitoExtension.class)
@ExtendWith(SystemStubsExtension.class)
class ProcessJourneyEventHandlerTest {
    private static final String PYI_UNRECOVERABLE_TIMEOUT_ERROR_PAGE = "pyi-timeout-unrecoverable";
    private static final String CODE = "code";
    private static final String IPV_SESSION_ID = "ipvSessionId";
    private static final String JOURNEY = "journey";
    private static final String MESSAGE = "message";
    private static final String STATUS_CODE = "statusCode";

    @Mock private Context mockContext;
    @Mock private IpvSessionService mockIpvSessionService;
    @Mock private ConfigService mockConfigService;
    @Mock private AuditService mockAuditService;
    @Mock private ClientOAuthSessionDetailsService mockClientOAuthSessionService;

    @SystemStub static EnvironmentVariables environmentVariables;

    @BeforeAll
    private static void beforeAll() {
        environmentVariables.set("IS_LOCAL", true);
    }

    @Test
    void shouldReturn400OnMissingJourneyStep() throws Exception {
        Map<String, String> input = Map.of(IPV_SESSION_ID, "1234");

        Map<String, Object> output =
                getProcessJourneyStepHandler().handleRequest(input, mockContext);

        assertEquals(HttpStatus.SC_BAD_REQUEST, output.get(STATUS_CODE));
        assertEquals(ErrorResponse.MISSING_JOURNEY_EVENT.getCode(), output.get(CODE));
        assertEquals(ErrorResponse.MISSING_JOURNEY_EVENT.getMessage(), output.get(MESSAGE));
    }

    @Test
    void shouldReturn400OnMissingSessionIdParam() throws Exception {
        Map<String, String> input = Map.of(JOURNEY, ProcessJourneyStepEvents.JOURNEY_NEXT);

        Map<String, Object> output =
                getProcessJourneyStepHandler().handleRequest(input, mockContext);

        assertEquals(HttpStatus.SC_BAD_REQUEST, output.get(STATUS_CODE));
        assertEquals(ErrorResponse.MISSING_IPV_SESSION_ID.getCode(), output.get(CODE));
        assertEquals(ErrorResponse.MISSING_IPV_SESSION_ID.getMessage(), output.get(MESSAGE));
    }

    @Test
    void shouldReturn400WhenInvalidSessionIdProvided() throws Exception {
        Map<String, String> input =
                Map.of(JOURNEY, ProcessJourneyStepEvents.JOURNEY_NEXT, IPV_SESSION_ID, "1234");

        Map<String, Object> output =
                getProcessJourneyStepHandler().handleRequest(input, mockContext);

        assertEquals(HttpStatus.SC_BAD_REQUEST, output.get(STATUS_CODE));
        assertEquals(ErrorResponse.INVALID_SESSION_ID.getCode(), output.get(CODE));
        assertEquals(ErrorResponse.INVALID_SESSION_ID.getMessage(), output.get(MESSAGE));
    }

    @Test
    void shouldReturn500WhenUnknownJourneyEngineStepProvided() throws Exception {
        Map<String, String> input =
                Map.of(JOURNEY, ProcessJourneyStepEvents.INVALID_STEP, IPV_SESSION_ID, "1234");

        mockIpvSessionItemAndTimeout(ProcessJourneyStepStates.INITIAL_IPV_JOURNEY_STATE);

        Map<String, Object> output =
                getProcessJourneyStepHandler().handleRequest(input, mockContext);

        assertEquals(HttpStatus.SC_INTERNAL_SERVER_ERROR, output.get(STATUS_CODE));
        assertEquals(ErrorResponse.FAILED_JOURNEY_ENGINE_STEP.getCode(), output.get(CODE));
        assertEquals(ErrorResponse.FAILED_JOURNEY_ENGINE_STEP.getMessage(), output.get(MESSAGE));
    }

    @Test
    void shouldReturn500WhenUserIsInUnknownState() throws Exception {
        Map<String, String> input =
                Map.of(JOURNEY, ProcessJourneyStepEvents.JOURNEY_NEXT, IPV_SESSION_ID, "1234");

        mockIpvSessionItemAndTimeout("INVALIDSTATE");

        Map<String, Object> output =
                getProcessJourneyStepHandler().handleRequest(input, mockContext);

        assertEquals(HttpStatus.SC_INTERNAL_SERVER_ERROR, output.get(STATUS_CODE));
        assertEquals(ErrorResponse.FAILED_JOURNEY_ENGINE_STEP.getCode(), output.get(CODE));
        assertEquals(ErrorResponse.FAILED_JOURNEY_ENGINE_STEP.getMessage(), output.get(MESSAGE));
    }

    @Test
    void shouldReturn500IfNoStateMachineMatchingJourneyType() throws IOException {
        Map<String, String> input =
                Map.of(JOURNEY, ProcessJourneyStepEvents.JOURNEY_NEXT, IPV_SESSION_ID, "1234");

        mockIpvSessionItemAndTimeout(ProcessJourneyStepStates.IPV_IDENTITY_START_PAGE_STATE);

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
    void shouldReturnErrorPageIfSessionHasExpired() throws Exception {
        Map<String, String> input =
                Map.of(JOURNEY, ProcessJourneyStepEvents.JOURNEY_NEXT, IPV_SESSION_ID, "1234");

        mockIpvSessionItemAndTimeout(ProcessJourneyStepStates.CRI_UK_PASSPORT_STATE);
        IpvSessionItem ipvSessionItem = mockIpvSessionService.getIpvSession("1234");
        ipvSessionItem.setCreationDateTime(Instant.now().minusSeconds(100).toString());
        when(mockConfigService.getSsmParameter(BACKEND_SESSION_TIMEOUT)).thenReturn("99");

        Map<String, Object> output =
                getProcessJourneyStepHandler().handleRequest(input, mockContext);

        ArgumentCaptor<IpvSessionItem> sessionArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(mockIpvSessionService).updateIpvSession(sessionArgumentCaptor.capture());

        IpvSessionItem capturedIpvSessionItem = sessionArgumentCaptor.getValue();
        assertEquals(
                ProcessJourneyStepStates.CORE_SESSION_TIMEOUT_STATE,
                sessionArgumentCaptor.getValue().getUserState());
        assertEquals(OAuth2Error.ACCESS_DENIED.getCode(), capturedIpvSessionItem.getErrorCode());
        assertEquals(
                OAuth2Error.ACCESS_DENIED.getDescription(),
                capturedIpvSessionItem.getErrorDescription());

        assertEquals(PYI_UNRECOVERABLE_TIMEOUT_ERROR_PAGE, output.get("page"));
    }

    @Test
    void shouldReturnSessionEndJourneyIfStateIsSessionTimeout() throws Exception {
        Map<String, String> input =
                Map.of(JOURNEY, ProcessJourneyStepEvents.JOURNEY_NEXT, IPV_SESSION_ID, "1234");

        IpvSessionItem ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setIpvSessionId(SecureTokenHelper.getInstance().generate());
        ipvSessionItem.setCreationDateTime(Instant.now().toString());
        ipvSessionItem.setUserState(ProcessJourneyStepStates.CORE_SESSION_TIMEOUT_STATE);
        ipvSessionItem.setClientOAuthSessionId(SecureTokenHelper.getInstance().generate());
        ipvSessionItem.setJourneyType(IPV_CORE_MAIN_JOURNEY);

        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);
        when(mockClientOAuthSessionService.getClientOAuthSession(any()))
                .thenReturn(getClientOAuthSessionItem());

        Map<String, Object> output =
                getProcessJourneyStepHandler().handleRequest(input, mockContext);

        ArgumentCaptor<IpvSessionItem> sessionArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(mockIpvSessionService).updateIpvSession(sessionArgumentCaptor.capture());
        assertEquals(
                ProcessJourneyStepStates.END_STATE,
                sessionArgumentCaptor.getValue().getUserState());

        assertEquals("/journey/build-client-oauth-response", output.get("journey"));
    }

    @Test
    void shouldClearOauthSessionIfItExists() throws Exception {
        Map<String, String> input =
                Map.of(JOURNEY, ProcessJourneyStepEvents.JOURNEY_NEXT, IPV_SESSION_ID, "1234");

        mockIpvSessionItemAndTimeout(ProcessJourneyStepStates.INITIAL_IPV_JOURNEY_STATE);

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
        Map<String, String> input = Map.of(JOURNEY, journeyEvent, IPV_SESSION_ID, "1234");

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
    void shouldSendAuditEventForMitigationStart() throws Exception {
        Map<String, String> input =
                Map.of(JOURNEY, "testWithMitigationStart", IPV_SESSION_ID, "1234");
        mockIpvSessionItemAndTimeout("CRI_STATE");
        when(mockConfigService.getSsmParameter(ConfigurationVariable.COMPONENT_ID))
                .thenReturn("component_id");

        getProcessJourneyStepHandler(StateMachineInitializerMode.TEST)
                .handleRequest(input, mockContext);

        ArgumentCaptor<AuditEvent> auditEventCaptor = ArgumentCaptor.forClass(AuditEvent.class);
        verify(mockAuditService).sendAuditEvent(auditEventCaptor.capture());
        AuditEvent capturedAuditEvent = auditEventCaptor.getValue();

        assertEquals(AuditEventTypes.IPV_MITIGATION_START, capturedAuditEvent.getEventName());
        assertEquals("component_id", capturedAuditEvent.getComponentId());
        assertEquals("testuserid", capturedAuditEvent.getUser().getUserId());
        assertEquals("testjourneyid", capturedAuditEvent.getUser().getGovukSigninJourneyId());
    }

    private void mockIpvSessionItemAndTimeout(String userState) {
        IpvSessionItem ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setIpvSessionId(SecureTokenHelper.getInstance().generate());
        ipvSessionItem.setCreationDateTime(Instant.now().toString());
        ipvSessionItem.setUserState(userState);
        ipvSessionItem.setClientOAuthSessionId(SecureTokenHelper.getInstance().generate());
        ipvSessionItem.setJourneyType(IPV_CORE_MAIN_JOURNEY);

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
        return new ProcessJourneyEventHandler(
                mockAuditService,
                mockIpvSessionService,
                mockConfigService,
                mockClientOAuthSessionService,
                List.of(IPV_CORE_MAIN_JOURNEY),
                stateMachineInitializerMode);
    }

    private ProcessJourneyEventHandler getProcessJourneyStepHandler() throws IOException {
        return getProcessJourneyStepHandler(StateMachineInitializerMode.STANDARD);
    }
}
