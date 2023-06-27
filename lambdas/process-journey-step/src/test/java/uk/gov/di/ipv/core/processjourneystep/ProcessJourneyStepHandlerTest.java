package uk.gov.di.ipv.core.processjourneystep;

import com.amazonaws.services.lambda.runtime.Context;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import org.apache.http.HttpStatus;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.config.EnvironmentVariable;
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
import static uk.gov.di.ipv.core.library.domain.IpvJourneyTypes.IPV_CORE_REFACTOR_JOURNEY;

@ExtendWith(MockitoExtension.class)
class ProcessJourneyStepHandlerTest {
    private static final String CODE = "code";
    private static final String IPV_SESSION_ID = "ipvSessionId";
    private static final String JOURNEY = "journey";
    private static final String MESSAGE = "message";
    private static final String STATUS_CODE = "statusCode";
    private static final int HTTP_STATUS_CODE_500 = 500;
    public static final String PRODUCTION = "production";
    public static final String INTEGRATION = "integration";
    public static final String STAGING = "staging";
    public static final String BUILD = "build";
    public static final String DEV = "dev";

    @Mock private Context mockContext;
    @Mock private IpvSessionService mockIpvSessionService;
    @Mock private ConfigService mockConfigService;
    @Mock private ClientOAuthSessionDetailsService mockClientOAuthSessionService;

    @Test
    void shouldReturn400OnMissingJourneyStep() throws Exception {
        Map<String, String> input = Map.of(IPV_SESSION_ID, "1234");

        when(mockConfigService.getEnvironmentVariable(EnvironmentVariable.ENVIRONMENT))
                .thenReturn(PRODUCTION);
        Map<String, Object> output =
                getProcessJourneyStepHandler().handleRequest(input, mockContext);

        assertEquals(HttpStatus.SC_BAD_REQUEST, output.get(STATUS_CODE));
        assertEquals(ErrorResponse.MISSING_JOURNEY_STEP.getCode(), output.get(CODE));
        assertEquals(ErrorResponse.MISSING_JOURNEY_STEP.getMessage(), output.get(MESSAGE));
    }

    @Test
    void shouldReturn400OnMissingSessionIdParam() throws Exception {
        Map<String, String> input = Map.of(JOURNEY, ProcessJourneyStepEvents.JOURNEY_NEXT);

        when(mockConfigService.getEnvironmentVariable(EnvironmentVariable.ENVIRONMENT))
                .thenReturn(PRODUCTION);
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

        when(mockConfigService.getEnvironmentVariable(EnvironmentVariable.ENVIRONMENT))
                .thenReturn(PRODUCTION);
        Map<String, Object> output =
                getProcessJourneyStepHandler().handleRequest(input, mockContext);

        assertEquals(HttpStatus.SC_BAD_REQUEST, output.get(STATUS_CODE));
        assertEquals(ErrorResponse.INVALID_SESSION_ID.getCode(), output.get(CODE));
        assertEquals(ErrorResponse.INVALID_SESSION_ID.getMessage(), output.get(MESSAGE));
    }

    @ParameterizedTest
    @ValueSource(strings = {DEV, BUILD, STAGING, INTEGRATION, PRODUCTION})
    void shouldReturn500WhenUnknownJourneyEngineStepProvided(String environment) throws Exception {
        Map<String, String> input =
                Map.of(JOURNEY, ProcessJourneyStepEvents.INVALID_STEP, IPV_SESSION_ID, "1234");

        mockIpvSessionItemAndTimeout(
                ProcessJourneyStepStates.INITIAL_IPV_JOURNEY_STATE, environment);

        Map<String, Object> output =
                getProcessJourneyStepHandler().handleRequest(input, mockContext);

        assertEquals(HttpStatus.SC_INTERNAL_SERVER_ERROR, output.get(STATUS_CODE));
        assertEquals(ErrorResponse.FAILED_JOURNEY_ENGINE_STEP.getCode(), output.get(CODE));
        assertEquals(ErrorResponse.FAILED_JOURNEY_ENGINE_STEP.getMessage(), output.get(MESSAGE));
    }

    @ParameterizedTest
    @ValueSource(strings = {DEV, BUILD, STAGING, INTEGRATION, PRODUCTION})
    void shouldReturn500WhenUserIsInUnknownState(String environment) throws Exception {
        Map<String, String> input =
                Map.of(JOURNEY, ProcessJourneyStepEvents.INVALID_STEP, IPV_SESSION_ID, "1234");

        mockIpvSessionItemAndTimeout("INVALID-STATE", environment);

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

        mockIpvSessionItemAndTimeout(
                ProcessJourneyStepStates.IPV_IDENTITY_START_PAGE_STATE, PRODUCTION);

        mockIpvSessionService.getIpvSession("anything").setJourneyType(IPV_CORE_REFACTOR_JOURNEY);

        Map<String, Object> output =
                getProcessJourneyStepHandler().handleRequest(input, mockContext);

        assertEquals(HttpStatus.SC_INTERNAL_SERVER_ERROR, output.get(STATUS_CODE));
        assertEquals(ErrorResponse.FAILED_JOURNEY_ENGINE_STEP.getCode(), output.get(CODE));
        assertEquals(ErrorResponse.FAILED_JOURNEY_ENGINE_STEP.getMessage(), output.get(MESSAGE));
    }

    @ParameterizedTest
    @ValueSource(strings = {DEV, BUILD, STAGING, INTEGRATION, PRODUCTION})
    void shouldReturnCheckExistingIdentityResponseWhenRequired(String environment)
            throws Exception {
        Map<String, String> input =
                Map.of(JOURNEY, ProcessJourneyStepEvents.JOURNEY_NEXT, IPV_SESSION_ID, "1234");

        mockIpvSessionItemAndTimeout(
                ProcessJourneyStepStates.IPV_IDENTITY_START_PAGE_STATE, environment);

        when(mockConfigService.getEnvironmentVariable(EnvironmentVariable.ENVIRONMENT))
                .thenReturn(environment);

        Map<String, Object> output =
                getProcessJourneyStepHandler().handleRequest(input, mockContext);

        assertEquals(
                ProcessJourneyStepEvents.JOURNEY_CHECK_EXISTING_IDENTITY, output.get("journey"));

        ArgumentCaptor<IpvSessionItem> sessionArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(mockIpvSessionService).updateIpvSession(sessionArgumentCaptor.capture());
        assertEquals(
                ProcessJourneyStepStates.CHECK_EXISTING_IDENTITY_STATE,
                sessionArgumentCaptor.getValue().getUserState());
    }

    @ParameterizedTest
    @ValueSource(strings = {DEV, BUILD, STAGING, INTEGRATION, PRODUCTION})
    void shouldReturnIdentityStartPageResponseWhenRequired(String environment) throws Exception {
        Map<String, String> input =
                Map.of(JOURNEY, ProcessJourneyStepEvents.JOURNEY_NEXT, IPV_SESSION_ID, "1234");

        mockIpvSessionItemAndTimeout(
                ProcessJourneyStepStates.INITIAL_IPV_JOURNEY_STATE, environment);

        Map<String, Object> output =
                getProcessJourneyStepHandler().handleRequest(input, mockContext);

        assertEquals(ProcessJourneyStepPages.IPV_IDENTITY_START_PAGE, output.get("page"));

        ArgumentCaptor<IpvSessionItem> sessionArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(mockIpvSessionService).updateIpvSession(sessionArgumentCaptor.capture());
        assertEquals(
                ProcessJourneyStepStates.IPV_IDENTITY_START_PAGE_STATE,
                sessionArgumentCaptor.getValue().getUserState());
    }

    @ParameterizedTest
    @ValueSource(strings = {DEV, BUILD, STAGING, INTEGRATION, PRODUCTION})
    void shouldReturnIdentityReusePageResponseWhenRequired(String environment) throws Exception {
        Map<String, String> input =
                Map.of(JOURNEY, ProcessJourneyStepEvents.JOURNEY_REUSE, IPV_SESSION_ID, "1234");

        mockIpvSessionItemAndTimeout(
                ProcessJourneyStepStates.CHECK_EXISTING_IDENTITY_STATE, environment);

        Map<String, Object> output =
                getProcessJourneyStepHandler().handleRequest(input, mockContext);

        assertEquals(ProcessJourneyStepPages.IPV_IDENTITY_REUSE_PAGE, output.get("page"));

        ArgumentCaptor<IpvSessionItem> sessionArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(mockIpvSessionService).updateIpvSession(sessionArgumentCaptor.capture());
        assertEquals(
                ProcessJourneyStepStates.IPV_IDENTITY_REUSE_PAGE_STATE,
                sessionArgumentCaptor.getValue().getUserState());
    }

    @ParameterizedTest
    @ValueSource(strings = {DEV, BUILD, STAGING, INTEGRATION, PRODUCTION})
    void shouldReturnEvaluateGpg45ScoresWhenIpvIdentityStartPageState(String environment)
            throws Exception {
        Map<String, String> input =
                Map.of(JOURNEY, ProcessJourneyStepEvents.JOURNEY_NEXT, IPV_SESSION_ID, "1234");

        mockIpvSessionItemAndTimeout(
                ProcessJourneyStepStates.CHECK_EXISTING_IDENTITY_STATE, environment);

        Map<String, Object> output =
                getProcessJourneyStepHandler().handleRequest(input, mockContext);

        ArgumentCaptor<IpvSessionItem> sessionArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(mockIpvSessionService).updateIpvSession(sessionArgumentCaptor.capture());
        assertEquals(
                ProcessJourneyStepStates.EVALUATE_GPG45_SCORES,
                sessionArgumentCaptor.getValue().getUserState());

        assertEquals(
                ProcessJourneyStepEvents.JOURNEY_EVALUATE_GPG_45_SCORES, output.get("journey"));
    }

    @ParameterizedTest
    @ValueSource(strings = {DEV, BUILD, STAGING, INTEGRATION, PRODUCTION})
    void shouldReturnEvaluateGpg45ScoresWhenCriUkPassportState(String environment)
            throws Exception {
        Map<String, String> input =
                Map.of(JOURNEY, ProcessJourneyStepEvents.JOURNEY_NEXT, IPV_SESSION_ID, "1234");

        mockIpvSessionItemAndTimeout(ProcessJourneyStepStates.CRI_UK_PASSPORT_STATE, environment);

        Map<String, Object> output =
                getProcessJourneyStepHandler().handleRequest(input, mockContext);

        ArgumentCaptor<IpvSessionItem> sessionArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(mockIpvSessionService).updateIpvSession(sessionArgumentCaptor.capture());
        assertEquals(
                ProcessJourneyStepStates.EVALUATE_GPG45_SCORES,
                sessionArgumentCaptor.getValue().getUserState());

        assertEquals(
                ProcessJourneyStepEvents.JOURNEY_EVALUATE_GPG_45_SCORES, output.get("journey"));
    }

    @ParameterizedTest
    @ValueSource(strings = {DEV, BUILD, STAGING, INTEGRATION, PRODUCTION})
    void shouldReturnCriErrorPageResponseIfPassportCriErrors(String environment) throws Exception {
        Map<String, String> input =
                Map.of(JOURNEY, ProcessJourneyStepEvents.ERROR, IPV_SESSION_ID, "1234");

        mockIpvSessionItemAndTimeout(ProcessJourneyStepStates.CRI_UK_PASSPORT_STATE, environment);

        Map<String, Object> output =
                getProcessJourneyStepHandler().handleRequest(input, mockContext);

        ArgumentCaptor<IpvSessionItem> sessionArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(mockIpvSessionService).updateIpvSession(sessionArgumentCaptor.capture());
        assertEquals(
                ProcessJourneyStepStates.CRI_ERROR_STATE,
                sessionArgumentCaptor.getValue().getUserState());

        assertEquals(ProcessJourneyStepEvents.ERROR, output.get("type"));
        assertEquals(ProcessJourneyStepPages.PYI_TECHNICAL_ERROR_PAGE, output.get("page"));
        assertEquals(HTTP_STATUS_CODE_500, output.get(STATUS_CODE));
        assertEquals(HttpStatus.SC_INTERNAL_SERVER_ERROR, output.get(STATUS_CODE));
    }

    @ParameterizedTest
    @ValueSource(strings = {DEV, BUILD, STAGING, INTEGRATION, PRODUCTION})
    void shouldReturnEvaluateGpg45ScoresWhenCriAddressState(String environment) throws Exception {
        Map<String, String> input =
                Map.of(JOURNEY, ProcessJourneyStepEvents.JOURNEY_NEXT, IPV_SESSION_ID, "1234");

        mockIpvSessionItemAndTimeout(ProcessJourneyStepStates.CRI_ADDRESS_STATE, environment);

        Map<String, Object> output =
                getProcessJourneyStepHandler().handleRequest(input, mockContext);

        ArgumentCaptor<IpvSessionItem> sessionArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(mockIpvSessionService).updateIpvSession(sessionArgumentCaptor.capture());
        assertEquals(
                ProcessJourneyStepStates.EVALUATE_GPG45_SCORES,
                sessionArgumentCaptor.getValue().getUserState());

        assertEquals(
                ProcessJourneyStepEvents.JOURNEY_EVALUATE_GPG_45_SCORES, output.get("journey"));
    }

    @ParameterizedTest
    @ValueSource(strings = {DEV, BUILD, STAGING, INTEGRATION, PRODUCTION})
    void shouldReturnCriErrorPageResponseIfAddressCriErrors(String environment) throws Exception {
        Map<String, String> input =
                Map.of(JOURNEY, ProcessJourneyStepEvents.ERROR, IPV_SESSION_ID, "1234");

        mockIpvSessionItemAndTimeout(ProcessJourneyStepStates.CRI_ADDRESS_STATE, environment);

        Map<String, Object> output =
                getProcessJourneyStepHandler().handleRequest(input, mockContext);

        ArgumentCaptor<IpvSessionItem> sessionArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(mockIpvSessionService).updateIpvSession(sessionArgumentCaptor.capture());
        assertEquals(
                ProcessJourneyStepStates.CRI_ERROR_STATE,
                sessionArgumentCaptor.getValue().getUserState());

        assertEquals(ProcessJourneyStepEvents.ERROR, output.get("type"));
        assertEquals(ProcessJourneyStepPages.PYI_TECHNICAL_ERROR_PAGE, output.get("page"));
        assertEquals(HTTP_STATUS_CODE_500, output.get(STATUS_CODE));
        assertEquals(HttpStatus.SC_INTERNAL_SERVER_ERROR, output.get(STATUS_CODE));
    }

    @ParameterizedTest
    @ValueSource(strings = {DEV, BUILD, STAGING, INTEGRATION, PRODUCTION})
    void shouldReturnEvaluateGpg45ScoresWhenCriFraudState(String environment) throws Exception {
        Map<String, String> input =
                Map.of(JOURNEY, ProcessJourneyStepEvents.JOURNEY_NEXT, IPV_SESSION_ID, "1234");

        mockIpvSessionItemAndTimeout(ProcessJourneyStepStates.CRI_FRAUD_STATE, environment);

        Map<String, Object> output =
                getProcessJourneyStepHandler().handleRequest(input, mockContext);

        ArgumentCaptor<IpvSessionItem> sessionArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(mockIpvSessionService).updateIpvSession(sessionArgumentCaptor.capture());
        assertEquals(
                ProcessJourneyStepStates.EVALUATE_GPG45_SCORES,
                sessionArgumentCaptor.getValue().getUserState());

        assertEquals(
                ProcessJourneyStepEvents.JOURNEY_EVALUATE_GPG_45_SCORES, output.get("journey"));
    }

    @ParameterizedTest
    @ValueSource(strings = {DEV, BUILD, STAGING, INTEGRATION, PRODUCTION})
    void shouldReturnCriErrorPageResponseIfFraudCriFails(String environment) throws Exception {
        Map<String, String> input =
                Map.of(JOURNEY, ProcessJourneyStepEvents.ERROR, IPV_SESSION_ID, "1234");

        mockIpvSessionItemAndTimeout(ProcessJourneyStepStates.CRI_FRAUD_STATE, environment);

        Map<String, Object> output =
                getProcessJourneyStepHandler().handleRequest(input, mockContext);

        ArgumentCaptor<IpvSessionItem> sessionArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(mockIpvSessionService).updateIpvSession(sessionArgumentCaptor.capture());
        assertEquals(
                ProcessJourneyStepStates.CRI_ERROR_STATE,
                sessionArgumentCaptor.getValue().getUserState());

        assertEquals(ProcessJourneyStepEvents.ERROR, output.get("type"));
        assertEquals(ProcessJourneyStepPages.PYI_TECHNICAL_ERROR_PAGE, output.get("page"));
        assertEquals(HTTP_STATUS_CODE_500, output.get(STATUS_CODE));
        assertEquals(HttpStatus.SC_INTERNAL_SERVER_ERROR, output.get(STATUS_CODE));
    }

    @ParameterizedTest
    @ValueSource(strings = {DEV, BUILD, STAGING, INTEGRATION, PRODUCTION})
    void shouldReturnEvaluateGpg45ScoresWhenCriKbvState(String environment) throws Exception {
        Map<String, String> input =
                Map.of(JOURNEY, ProcessJourneyStepEvents.JOURNEY_NEXT, IPV_SESSION_ID, "1234");

        mockIpvSessionItemAndTimeout(ProcessJourneyStepStates.CRI_KBV_STATE, environment);

        Map<String, Object> output =
                getProcessJourneyStepHandler().handleRequest(input, mockContext);

        ArgumentCaptor<IpvSessionItem> sessionArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(mockIpvSessionService).updateIpvSession(sessionArgumentCaptor.capture());
        assertEquals(
                ProcessJourneyStepStates.EVALUATE_GPG45_SCORES,
                sessionArgumentCaptor.getValue().getUserState());

        assertEquals(
                ProcessJourneyStepEvents.JOURNEY_EVALUATE_GPG_45_SCORES, output.get("journey"));
    }

    @ParameterizedTest
    @ValueSource(strings = {DEV, BUILD, STAGING, INTEGRATION, PRODUCTION})
    void shouldReturnCriErrorPageResponseIfKbvCriErrors(String environment) throws Exception {
        Map<String, String> input =
                Map.of(JOURNEY, ProcessJourneyStepEvents.ERROR, IPV_SESSION_ID, "1234");

        mockIpvSessionItemAndTimeout(ProcessJourneyStepStates.CRI_KBV_STATE, environment);

        Map<String, Object> output =
                getProcessJourneyStepHandler().handleRequest(input, mockContext);

        ArgumentCaptor<IpvSessionItem> sessionArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(mockIpvSessionService).updateIpvSession(sessionArgumentCaptor.capture());
        assertEquals(
                ProcessJourneyStepStates.CRI_ERROR_STATE,
                sessionArgumentCaptor.getValue().getUserState());

        assertEquals(ProcessJourneyStepEvents.ERROR, output.get("type"));
        assertEquals(ProcessJourneyStepPages.PYI_TECHNICAL_ERROR_PAGE, output.get("page"));
        assertEquals(HTTP_STATUS_CODE_500, output.get(STATUS_CODE));
        assertEquals(HttpStatus.SC_INTERNAL_SERVER_ERROR, output.get(STATUS_CODE));
    }

    @ParameterizedTest
    @ValueSource(strings = {DEV, BUILD, STAGING, INTEGRATION, PRODUCTION})
    void shouldReturnEndSessionJourneyResponseWhenRequired(String environment) throws Exception {
        Map<String, String> input =
                Map.of(JOURNEY, ProcessJourneyStepEvents.JOURNEY_NEXT, IPV_SESSION_ID, "1234");

        mockIpvSessionItemAndTimeout(ProcessJourneyStepStates.IPV_SUCCESS_PAGE_STATE, environment);

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

    @ParameterizedTest
    @ValueSource(strings = {DEV, BUILD, STAGING, INTEGRATION, PRODUCTION})
    void shouldReturnDebugEvaluateGpg45ScoresJourneyWhenRequired(String environment)
            throws Exception {
        Map<String, String> input =
                Map.of(JOURNEY, ProcessJourneyStepEvents.JOURNEY_NEXT, IPV_SESSION_ID, "1234");

        mockIpvSessionItemAndTimeout(ProcessJourneyStepStates.DEBUG_PAGE_STATE, environment);

        Map<String, Object> output =
                getProcessJourneyStepHandler().handleRequest(input, mockContext);

        ArgumentCaptor<IpvSessionItem> sessionArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(mockIpvSessionService).updateIpvSession(sessionArgumentCaptor.capture());
        assertEquals(
                ProcessJourneyStepStates.DEBUG_EVALUATE_GPG45_SCORES,
                sessionArgumentCaptor.getValue().getUserState());

        assertEquals(
                ProcessJourneyStepEvents.JOURNEY_EVALUATE_GPG_45_SCORES, output.get("journey"));
    }

    @ParameterizedTest
    @ValueSource(strings = {DEV, BUILD, STAGING, INTEGRATION, PRODUCTION})
    void shouldReturnPYITechnicalPageIfErrorOccursOnDebugJourney(String environment)
            throws Exception {
        Map<String, String> input =
                Map.of(JOURNEY, ProcessJourneyStepEvents.ERROR, IPV_SESSION_ID, "1234");

        mockIpvSessionItemAndTimeout(ProcessJourneyStepStates.DEBUG_PAGE_STATE, environment);

        Map<String, Object> output =
                getProcessJourneyStepHandler().handleRequest(input, mockContext);

        ArgumentCaptor<IpvSessionItem> sessionArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(mockIpvSessionService).updateIpvSession(sessionArgumentCaptor.capture());
        assertEquals(
                ProcessJourneyStepStates.CRI_ERROR_STATE,
                sessionArgumentCaptor.getValue().getUserState());

        assertEquals(ProcessJourneyStepEvents.ERROR, output.get("type"));
        assertEquals(ProcessJourneyStepPages.PYI_TECHNICAL_ERROR_PAGE, output.get("page"));
        assertEquals(HTTP_STATUS_CODE_500, output.get(STATUS_CODE));
        assertEquals(HttpStatus.SC_INTERNAL_SERVER_ERROR, output.get(STATUS_CODE));
    }

    @ParameterizedTest
    @ValueSource(strings = {DEV, BUILD, STAGING, INTEGRATION, PRODUCTION})
    void shouldReturnPYINoMatchPageIfAccessDeniedOccursOnDebugJourney(String environment)
            throws Exception {
        Map<String, String> input =
                Map.of(JOURNEY, ProcessJourneyStepEvents.ACCESS_DENIED, IPV_SESSION_ID, "1234");

        mockIpvSessionItemAndTimeout(ProcessJourneyStepStates.DEBUG_PAGE_STATE, environment);

        Map<String, Object> output =
                getProcessJourneyStepHandler().handleRequest(input, mockContext);

        ArgumentCaptor<IpvSessionItem> sessionArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(mockIpvSessionService).updateIpvSession(sessionArgumentCaptor.capture());
        assertEquals(
                ProcessJourneyStepStates.PYI_NO_MATCH_STATE,
                sessionArgumentCaptor.getValue().getUserState());

        assertEquals(ProcessJourneyStepPages.PYI_NO_MATCH_PAGE, output.get("page"));
    }

    @ParameterizedTest
    @ValueSource(strings = {DEV, BUILD, STAGING, INTEGRATION, PRODUCTION})
    void shouldReturnErrorPageResponseWhenRequired(String environment) throws Exception {
        Map<String, String> input =
                Map.of(JOURNEY, ProcessJourneyStepEvents.JOURNEY_NEXT, IPV_SESSION_ID, "1234");

        mockIpvSessionItemAndTimeout(ProcessJourneyStepStates.CRI_ERROR_STATE, environment);

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

    @ParameterizedTest
    @ValueSource(strings = {DEV, BUILD, STAGING, INTEGRATION, PRODUCTION})
    void shouldReturnPYINoMatchPageIfCriStateReceivesAccessDenied(String environment)
            throws Exception {
        Map<String, String> input =
                Map.of(JOURNEY, ProcessJourneyStepEvents.ACCESS_DENIED, IPV_SESSION_ID, "1234");

        mockIpvSessionItemAndTimeout(ProcessJourneyStepStates.CRI_UK_PASSPORT_STATE, environment);

        Map<String, Object> output =
                getProcessJourneyStepHandler().handleRequest(input, mockContext);

        ArgumentCaptor<IpvSessionItem> sessionArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(mockIpvSessionService).updateIpvSession(sessionArgumentCaptor.capture());
        assertEquals(
                ProcessJourneyStepStates.PYI_NO_MATCH_STATE,
                sessionArgumentCaptor.getValue().getUserState());

        assertEquals(ProcessJourneyStepPages.PYI_NO_MATCH_PAGE, output.get("page"));
    }

    @ParameterizedTest
    @ValueSource(strings = {DEV, BUILD, STAGING, INTEGRATION, PRODUCTION})
    void shouldReturnPYITechnicalPageIfCriStateReceivesError(String environment) throws Exception {
        Map<String, String> input =
                Map.of(JOURNEY, ProcessJourneyStepEvents.ERROR, IPV_SESSION_ID, "1234");

        mockIpvSessionItemAndTimeout(ProcessJourneyStepStates.CRI_FRAUD_STATE, environment);

        Map<String, Object> output =
                getProcessJourneyStepHandler().handleRequest(input, mockContext);

        ArgumentCaptor<IpvSessionItem> sessionArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(mockIpvSessionService).updateIpvSession(sessionArgumentCaptor.capture());
        assertEquals(
                ProcessJourneyStepStates.CRI_ERROR_STATE,
                sessionArgumentCaptor.getValue().getUserState());

        assertEquals(ProcessJourneyStepEvents.ERROR, output.get("type"));
        assertEquals(ProcessJourneyStepPages.PYI_TECHNICAL_ERROR_PAGE, output.get("page"));
        assertEquals(HTTP_STATUS_CODE_500, output.get(STATUS_CODE));
        assertEquals(HttpStatus.SC_INTERNAL_SERVER_ERROR, output.get(STATUS_CODE));
    }

    @ParameterizedTest
    @ValueSource(strings = {DEV, BUILD, STAGING, INTEGRATION, PRODUCTION})
    void shouldReturnPyiNoMatchPageIfInSelectCRIStateAndReturnsPyiNoMatchJourney(String environment)
            throws Exception {
        Map<String, String> input =
                Map.of(JOURNEY, ProcessJourneyStepPages.PYI_NO_MATCH_PAGE, IPV_SESSION_ID, "1234");

        mockIpvSessionItemAndTimeout(ProcessJourneyStepStates.SELECT_CRI_STATE, environment);

        Map<String, Object> output =
                getProcessJourneyStepHandler().handleRequest(input, mockContext);

        ArgumentCaptor<IpvSessionItem> sessionArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(mockIpvSessionService).updateIpvSession(sessionArgumentCaptor.capture());
        assertEquals(
                ProcessJourneyStepStates.PYI_NO_MATCH_STATE,
                sessionArgumentCaptor.getValue().getUserState());

        assertEquals(ProcessJourneyStepPages.PYI_NO_MATCH_PAGE, output.get("page"));
    }

    @ParameterizedTest
    @ValueSource(strings = {DEV, BUILD, STAGING, INTEGRATION, PRODUCTION})
    void shouldReturnPYITechnicalErrorIfSelectCRIReturnsFail(String environment) throws Exception {
        Map<String, String> input =
                Map.of(JOURNEY, ProcessJourneyStepEvents.FAIL, IPV_SESSION_ID, "1234");

        mockIpvSessionItemAndTimeout(ProcessJourneyStepStates.SELECT_CRI_STATE, environment);

        Map<String, Object> output =
                getProcessJourneyStepHandler().handleRequest(input, mockContext);

        ArgumentCaptor<IpvSessionItem> sessionArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(mockIpvSessionService).updateIpvSession(sessionArgumentCaptor.capture());
        assertEquals(
                ProcessJourneyStepStates.SELECT_CRI_ERROR_STATE,
                sessionArgumentCaptor.getValue().getUserState());
        assertEquals(ProcessJourneyStepPages.PYI_TECHNICAL_ERROR_PAGE, output.get("page"));
        assertEquals(HTTP_STATUS_CODE_500, output.get(STATUS_CODE));
    }

    @ParameterizedTest
    @ValueSource(strings = {DEV, BUILD, STAGING, INTEGRATION, PRODUCTION})
    void shouldReturnEvaluateGpg45ScoresJourneyIfInDcmawStateReturnsAccessDeniedResponse(
            String environment) throws Exception {
        Map<String, String> input =
                Map.of(JOURNEY, ProcessJourneyStepEvents.ACCESS_DENIED, IPV_SESSION_ID, "1234");

        mockIpvSessionItemAndTimeout(ProcessJourneyStepStates.CRI_DCMAW_STATE, environment);

        Map<String, Object> output =
                getProcessJourneyStepHandler().handleRequest(input, mockContext);

        ArgumentCaptor<IpvSessionItem> sessionArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(mockIpvSessionService).updateIpvSession(sessionArgumentCaptor.capture());
        assertEquals(
                ProcessJourneyStepStates.EVALUATE_GPG45_SCORES,
                sessionArgumentCaptor.getValue().getUserState());

        assertEquals(
                ProcessJourneyStepEvents.JOURNEY_EVALUATE_GPG_45_SCORES, output.get("journey"));
    }

    @ParameterizedTest
    @ValueSource(strings = {DEV, BUILD, STAGING, INTEGRATION, PRODUCTION})
    void shouldReturnErrorPageIfSessionHasExpired(String environment) throws Exception {
        Map<String, String> input =
                Map.of(JOURNEY, ProcessJourneyStepEvents.JOURNEY_NEXT, IPV_SESSION_ID, "1234");

        IpvSessionItem ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setIpvSessionId(SecureTokenHelper.generate());
        ipvSessionItem.setCreationDateTime(Instant.now().minusSeconds(100).toString());
        ipvSessionItem.setUserState(ProcessJourneyStepStates.CRI_UK_PASSPORT_STATE);
        ipvSessionItem.setClientOAuthSessionId(SecureTokenHelper.generate());
        ipvSessionItem.setJourneyType(IPV_CORE_MAIN_JOURNEY);

        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);
        when(mockConfigService.getSsmParameter(BACKEND_SESSION_TIMEOUT)).thenReturn("99");
        when(mockConfigService.getSsmParameter(BACKEND_SESSION_TIMEOUT)).thenReturn("99");
        when(mockConfigService.getEnvironmentVariable(EnvironmentVariable.ENVIRONMENT))
                .thenReturn(environment);
        when(mockIpvSessionService.getIpvSession("1234")).thenReturn(ipvSessionItem);
        when(mockClientOAuthSessionService.getClientOAuthSession(any()))
                .thenReturn(getClientOAuthSessionItem());

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

    @ParameterizedTest
    @ValueSource(strings = {DEV, BUILD, STAGING, INTEGRATION, PRODUCTION})
    void shouldReturnSessionEndJourneyIfStateIsSessionTimeout(String environment) throws Exception {
        Map<String, String> input =
                Map.of(JOURNEY, ProcessJourneyStepEvents.JOURNEY_NEXT, IPV_SESSION_ID, "1234");

        IpvSessionItem ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setIpvSessionId(SecureTokenHelper.generate());
        ipvSessionItem.setCreationDateTime(Instant.now().minusSeconds(100).toString());
        ipvSessionItem.setUserState(ProcessJourneyStepStates.CORE_SESSION_TIMEOUT_STATE);
        ipvSessionItem.setClientOAuthSessionId(SecureTokenHelper.generate());
        ipvSessionItem.setJourneyType(IPV_CORE_MAIN_JOURNEY);

        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);
        when(mockConfigService.getEnvironmentVariable(EnvironmentVariable.ENVIRONMENT))
                .thenReturn(environment);
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

    @ParameterizedTest
    @ValueSource(strings = {DEV, BUILD, STAGING, INTEGRATION, PRODUCTION})
    void shouldClearOauthSessionIfItExists(String environment) throws Exception {
        Map<String, String> input =
                Map.of(JOURNEY, ProcessJourneyStepEvents.JOURNEY_NEXT, IPV_SESSION_ID, "1234");

        IpvSessionItem ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setIpvSessionId(SecureTokenHelper.generate());
        ipvSessionItem.setCriOAuthSessionId(SecureTokenHelper.generate());
        ipvSessionItem.setCreationDateTime(Instant.now().toString());
        ipvSessionItem.setUserState(ProcessJourneyStepStates.IPV_IDENTITY_START_PAGE_STATE);
        ipvSessionItem.setClientOAuthSessionId(SecureTokenHelper.generate());
        ipvSessionItem.setJourneyType(IPV_CORE_MAIN_JOURNEY);

        when(mockConfigService.getSsmParameter(BACKEND_SESSION_TIMEOUT)).thenReturn("7200");
        when(mockConfigService.getEnvironmentVariable(EnvironmentVariable.ENVIRONMENT))
                .thenReturn(environment);
        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);
        when(mockClientOAuthSessionService.getClientOAuthSession(any()))
                .thenReturn(getClientOAuthSessionItem());

        getProcessJourneyStepHandler().handleRequest(input, mockContext);

        ArgumentCaptor<IpvSessionItem> sessionArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(mockIpvSessionService).updateIpvSession(sessionArgumentCaptor.capture());
        assertNull(sessionArgumentCaptor.getValue().getCriOAuthSessionId());
    }

    private void mockIpvSessionItemAndTimeout(String validateOauthCallback, String environment) {
        IpvSessionItem ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setIpvSessionId(SecureTokenHelper.generate());
        ipvSessionItem.setCreationDateTime(Instant.now().toString());
        ipvSessionItem.setUserState(validateOauthCallback);
        ipvSessionItem.setClientOAuthSessionId(SecureTokenHelper.generate());
        ipvSessionItem.setJourneyType(IPV_CORE_MAIN_JOURNEY);

        when(mockConfigService.getSsmParameter(BACKEND_SESSION_TIMEOUT)).thenReturn("7200");
        when(mockConfigService.getEnvironmentVariable(EnvironmentVariable.ENVIRONMENT))
                .thenReturn(environment);
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
