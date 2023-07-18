package uk.gov.di.ipv.core.processjourneystep;

import com.amazonaws.services.lambda.runtime.Context;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import org.apache.http.HttpStatus;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.helpers.SecureTokenHelper;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.ClientOAuthSessionDetailsService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.processjourneystep.utils.ProcessJourneyStepEvents;
import uk.gov.di.ipv.core.processjourneystep.utils.ProcessJourneyStepPages;
import uk.gov.di.ipv.core.processjourneystep.utils.ProcessJourneyStepStates;
import uk.org.webcompere.systemstubs.environment.EnvironmentVariables;
import uk.org.webcompere.systemstubs.jupiter.SystemStub;
import uk.org.webcompere.systemstubs.jupiter.SystemStubsExtension;

import java.io.IOException;
import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.BACKEND_SESSION_TIMEOUT;
import static uk.gov.di.ipv.core.library.domain.IpvJourneyTypes.IPV_CORE_MAIN_JOURNEY;

@ExtendWith(MockitoExtension.class)
@ExtendWith(SystemStubsExtension.class)
class ProcessJourneyStepHandlerTest {
    private static final String CODE = "code";
    private static final String IPV_SESSION_ID = "ipvSessionId";
    private static final String JOURNEY = "journey";
    private static final String MESSAGE = "message";
    private static final String STATUS_CODE = "statusCode";

    @Mock private Context mockContext;
    @Mock private IpvSessionService mockIpvSessionService;
    @Mock private ConfigService mockConfigService;
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
        assertEquals(ErrorResponse.MISSING_JOURNEY_STEP.getCode(), output.get(CODE));
        assertEquals(ErrorResponse.MISSING_JOURNEY_STEP.getMessage(), output.get(MESSAGE));
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

        mockIpvSessionItemAndTimeout("INVALID-STATE");

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

        ProcessJourneyStepHandler processJourneyStepHandler =
                new ProcessJourneyStepHandler(
                        mockIpvSessionService,
                        mockConfigService,
                        mockClientOAuthSessionService,
                        List.of());

        Map<String, Object> output = processJourneyStepHandler.handleRequest(input, mockContext);

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

        assertEquals(
                ProcessJourneyStepPages.PYI_UNRECOVERABLE_TIMEOUT_ERROR_PAGE, output.get("page"));
    }

    @Test
    void shouldReturnSessionEndJourneyIfStateIsSessionTimeout() throws Exception {
        Map<String, String> input =
                Map.of(JOURNEY, ProcessJourneyStepEvents.JOURNEY_NEXT, IPV_SESSION_ID, "1234");

        IpvSessionItem ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setIpvSessionId(SecureTokenHelper.generate());
        ipvSessionItem.setCreationDateTime(Instant.now().toString());
        ipvSessionItem.setUserState("SUB_JOURNEY_A_AND_F_J2/CRI_FRAUD");
        ipvSessionItem.setClientOAuthSessionId(SecureTokenHelper.generate());
        ipvSessionItem.setJourneyType(IPV_CORE_MAIN_JOURNEY);

        when(mockConfigService.getSsmParameter(BACKEND_SESSION_TIMEOUT)).thenReturn("200");
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

    private void mockIpvSessionItemAndTimeout(String userState) {
        IpvSessionItem ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setIpvSessionId(SecureTokenHelper.generate());
        ipvSessionItem.setCreationDateTime(Instant.now().toString());
        ipvSessionItem.setUserState(userState);
        ipvSessionItem.setClientOAuthSessionId(SecureTokenHelper.generate());
        ipvSessionItem.setJourneyType(IPV_CORE_MAIN_JOURNEY);

        when(mockConfigService.getSsmParameter(BACKEND_SESSION_TIMEOUT)).thenReturn("7200");
        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);
        when(mockClientOAuthSessionService.getClientOAuthSession(any()))
                .thenReturn(getClientOAuthSessionItem());
    }

    private ClientOAuthSessionItem getClientOAuthSessionItem() {
        return ClientOAuthSessionItem.builder()
                .clientOAuthSessionId(SecureTokenHelper.generate())
                .responseType("code")
                .state("test-state")
                .redirectUri("https://example.com/redirect")
                .govukSigninJourneyId("test-journey-id")
                .userId("test-user-id")
                .build();
    }

    private ProcessJourneyStepHandler getProcessJourneyStepHandler() throws IOException {
        return new ProcessJourneyStepHandler(
                mockIpvSessionService,
                mockConfigService,
                mockClientOAuthSessionService,
                List.of(IPV_CORE_MAIN_JOURNEY));
    }
}
