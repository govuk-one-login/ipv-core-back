package uk.gov.di.ipv.core.processjourneystep;

import com.amazonaws.services.lambda.runtime.Context;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import org.apache.http.HttpStatus;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.config.EnvironmentVariable;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.IpvJourneyTypes;
import uk.gov.di.ipv.core.library.dto.ClientSessionDetailsDto;
import uk.gov.di.ipv.core.library.dto.CredentialIssuerSessionDetailsDto;
import uk.gov.di.ipv.core.library.helpers.SecureTokenHelper;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.processjourneystep.utils.ProcessJourneyStepEvents;
import uk.gov.di.ipv.core.processjourneystep.utils.ProcessJourneyStepPages;
import uk.gov.di.ipv.core.processjourneystep.utils.ProcessJourneyStepStates;

import java.time.Instant;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.BACKEND_SESSION_TIMEOUT;

@ExtendWith(MockitoExtension.class)
class ProcessJourneyStepHandlerTest {
    private static final String CODE = "code";
    private static final String IPV_SESSION_ID = "ipvSessionId";
    private static final String JOURNEY = "journey";
    private static final String MESSAGE = "message";
    private static final String STATUS_CODE = "statusCode";
    private static final int HTTP_STATUS_CODE_500 = 500;

    @Mock private Context mockContext;
    @Mock private IpvSessionService mockIpvSessionService;
    @Mock private ConfigService mockConfigService;

    private ProcessJourneyStepHandler processJourneyStepHandler;
    private ClientSessionDetailsDto clientSessionDetailsDto;

    @BeforeEach
    void setUp() {
        processJourneyStepHandler =
                new ProcessJourneyStepHandler(mockIpvSessionService, mockConfigService);
        clientSessionDetailsDto = new ClientSessionDetailsDto();
    }

    @ParameterizedTest
    @ValueSource(strings = {"dev", "build", "staging", "integration", "production"})
    void shouldReturn400OnMissingJourneyStep() {
        Map<String, String> input = Map.of(IPV_SESSION_ID, "1234");

        Map<String, Object> output = processJourneyStepHandler.handleRequest(input, mockContext);

        assertEquals(HttpStatus.SC_BAD_REQUEST, output.get(STATUS_CODE));
        assertEquals(ErrorResponse.MISSING_JOURNEY_STEP.getCode(), output.get(CODE));
        assertEquals(ErrorResponse.MISSING_JOURNEY_STEP.getMessage(), output.get(MESSAGE));
    }

    @ParameterizedTest
    @ValueSource(strings = {"dev", "build", "staging", "integration", "production"})
    void shouldReturn400OnMissingJourneyStepParam() {
        Map<String, String> input = Map.of(JOURNEY, ProcessJourneyStepEvents.JOURNEY_NEXT);

        Map<String, Object> output = processJourneyStepHandler.handleRequest(input, mockContext);

        assertEquals(HttpStatus.SC_BAD_REQUEST, output.get(STATUS_CODE));
        assertEquals(ErrorResponse.MISSING_IPV_SESSION_ID.getCode(), output.get(CODE));
        assertEquals(ErrorResponse.MISSING_IPV_SESSION_ID.getMessage(), output.get(MESSAGE));
    }

    @ParameterizedTest
    @ValueSource(strings = {"dev", "build", "staging", "integration", "production"})
    void shouldReturn400WhenInvalidSessionIdProvided() {
        Map<String, String> input =
                Map.of(JOURNEY, ProcessJourneyStepEvents.JOURNEY_NEXT, IPV_SESSION_ID, "1234");

        when(mockIpvSessionService.getIpvSession("1234")).thenReturn(null);

        Map<String, Object> output = processJourneyStepHandler.handleRequest(input, mockContext);

        assertEquals(HttpStatus.SC_BAD_REQUEST, output.get(STATUS_CODE));
        assertEquals(ErrorResponse.INVALID_SESSION_ID.getCode(), output.get(CODE));
        assertEquals(ErrorResponse.INVALID_SESSION_ID.getMessage(), output.get(MESSAGE));
    }

    @ParameterizedTest
    @ValueSource(strings = {"dev", "build", "staging", "integration", "production"})
    void shouldReturn500WhenUnknownJourneyEngineStepProvided(String environment) {
        Map<String, String> input =
                Map.of(JOURNEY, ProcessJourneyStepEvents.INVALID_STEP, IPV_SESSION_ID, "1234");

        mockIpvSessionItemAndTimeout(
                ProcessJourneyStepStates.INITIAL_IPV_JOURNEY_STATE, environment);

        Map<String, Object> output = processJourneyStepHandler.handleRequest(input, mockContext);

        assertEquals(HttpStatus.SC_INTERNAL_SERVER_ERROR, output.get(STATUS_CODE));
        assertEquals(ErrorResponse.FAILED_JOURNEY_ENGINE_STEP.getCode(), output.get(CODE));
        assertEquals(ErrorResponse.FAILED_JOURNEY_ENGINE_STEP.getMessage(), output.get(MESSAGE));
    }

    @ParameterizedTest
    @ValueSource(strings = {"dev", "build", "staging", "integration", "production"})
    void shouldReturn500WhenUserIsInUnknownState(String environment) {
        Map<String, String> input =
                Map.of(JOURNEY, ProcessJourneyStepEvents.INVALID_STEP, IPV_SESSION_ID, "1234");

        mockIpvSessionItemAndTimeout("INVALID-STATE", environment);

        Map<String, Object> output = processJourneyStepHandler.handleRequest(input, mockContext);

        assertEquals(HttpStatus.SC_INTERNAL_SERVER_ERROR, output.get(STATUS_CODE));
        assertEquals(ErrorResponse.FAILED_JOURNEY_ENGINE_STEP.getCode(), output.get(CODE));
        assertEquals(ErrorResponse.FAILED_JOURNEY_ENGINE_STEP.getMessage(), output.get(MESSAGE));
    }

    @ParameterizedTest
    @ValueSource(strings = {"dev", "build", "staging", "integration", "production"})
    void shouldReturnCheckExistingIdentityResponseWhenRequired(String environment) {
        Map<String, String> input =
                Map.of(JOURNEY, ProcessJourneyStepEvents.JOURNEY_NEXT, IPV_SESSION_ID, "1234");

        mockIpvSessionItemAndTimeout(
                ProcessJourneyStepStates.IPV_IDENTITY_START_PAGE_STATE, environment);

        when(mockConfigService.getEnvironmentVariable(EnvironmentVariable.ENVIRONMENT))
                .thenReturn(environment);

        Map<String, Object> output = processJourneyStepHandler.handleRequest(input, mockContext);

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
    @ValueSource(strings = {"dev", "build", "staging", "integration", "production"})
    void shouldReturnIdentityStartPageResponseWhenRequired(String environment) {
        Map<String, String> input =
                Map.of(JOURNEY, ProcessJourneyStepEvents.JOURNEY_NEXT, IPV_SESSION_ID, "1234");

        mockIpvSessionItemAndTimeout(
                ProcessJourneyStepStates.INITIAL_IPV_JOURNEY_STATE, environment);

        Map<String, Object> output = processJourneyStepHandler.handleRequest(input, mockContext);

        assertEquals(ProcessJourneyStepPages.IPV_IDENTITY_START_PAGE, output.get("page"));

        ArgumentCaptor<IpvSessionItem> sessionArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(mockIpvSessionService).updateIpvSession(sessionArgumentCaptor.capture());
        assertEquals(
                ProcessJourneyStepStates.IPV_IDENTITY_START_PAGE_STATE,
                sessionArgumentCaptor.getValue().getUserState());
    }

    @ParameterizedTest
    @ValueSource(strings = {"dev", "build", "staging", "integration", "production"})
    void shouldReturnIdentityReusePageResponseWhenRequired(String environment) {
        Map<String, String> input =
                Map.of(JOURNEY, ProcessJourneyStepEvents.JOURNEY_REUSE, IPV_SESSION_ID, "1234");

        mockIpvSessionItemAndTimeout(
                ProcessJourneyStepStates.CHECK_EXISTING_IDENTITY_STATE, environment);

        Map<String, Object> output = processJourneyStepHandler.handleRequest(input, mockContext);

        assertEquals(ProcessJourneyStepPages.IPV_IDENTITY_REUSE_PAGE, output.get("page"));

        ArgumentCaptor<IpvSessionItem> sessionArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(mockIpvSessionService).updateIpvSession(sessionArgumentCaptor.capture());
        assertEquals(
                ProcessJourneyStepStates.IPV_IDENTITY_REUSE_PAGE_STATE,
                sessionArgumentCaptor.getValue().getUserState());
    }

    @ParameterizedTest
    @ValueSource(strings = {"dev", "build", "staging", "integration", "production"})
    void shouldReturnEvaluateGpg45ScoresWhenIpvIdentityStartPageState(String environment) {
        Map<String, String> input =
                Map.of(JOURNEY, ProcessJourneyStepEvents.JOURNEY_NEXT, IPV_SESSION_ID, "1234");

        mockIpvSessionItemAndTimeout(
                ProcessJourneyStepStates.CHECK_EXISTING_IDENTITY_STATE, environment);

        Map<String, Object> output = processJourneyStepHandler.handleRequest(input, mockContext);

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
    @ValueSource(strings = {"dev", "build", "staging", "integration", "production"})
    void shouldReturnEvaluateGpg45ScoresWhenCriUkPassportState(String environment) {
        Map<String, String> input =
                Map.of(JOURNEY, ProcessJourneyStepEvents.JOURNEY_NEXT, IPV_SESSION_ID, "1234");

        mockIpvSessionItemAndTimeout(ProcessJourneyStepStates.CRI_UK_PASSPORT_STATE, environment);

        Map<String, Object> output = processJourneyStepHandler.handleRequest(input, mockContext);

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
    @ValueSource(strings = {"dev", "build", "staging", "integration", "production"})
    void shouldReturnCriErrorPageResponseIfPassportCriErrors(String environment) {
        Map<String, String> input =
                Map.of(JOURNEY, ProcessJourneyStepEvents.ERROR, IPV_SESSION_ID, "1234");

        mockIpvSessionItemAndTimeout(ProcessJourneyStepStates.CRI_UK_PASSPORT_STATE, environment);

        Map<String, Object> output = processJourneyStepHandler.handleRequest(input, mockContext);

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
    @ValueSource(strings = {"dev", "build", "staging", "integration", "production"})
    void shouldReturnEvaluateGpg45ScoresWhenCriAddressState(String environment) {
        Map<String, String> input =
                Map.of(JOURNEY, ProcessJourneyStepEvents.JOURNEY_NEXT, IPV_SESSION_ID, "1234");

        mockIpvSessionItemAndTimeout(ProcessJourneyStepStates.CRI_ADDRESS_STATE, environment);

        Map<String, Object> output = processJourneyStepHandler.handleRequest(input, mockContext);

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
    @ValueSource(strings = {"dev", "build", "staging", "integration", "production"})
    void shouldReturnCriErrorPageResponseIfAddressCriErrors(String environment) {
        Map<String, String> input =
                Map.of(JOURNEY, ProcessJourneyStepEvents.ERROR, IPV_SESSION_ID, "1234");

        mockIpvSessionItemAndTimeout(ProcessJourneyStepStates.CRI_ADDRESS_STATE, environment);

        Map<String, Object> output = processJourneyStepHandler.handleRequest(input, mockContext);

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
    @ValueSource(strings = {"dev", "build", "staging", "integration", "production"})
    void shouldReturnEvaluateGpg45ScoresWhenCriFraudState(String environment) {
        Map<String, String> input =
                Map.of(JOURNEY, ProcessJourneyStepEvents.JOURNEY_NEXT, IPV_SESSION_ID, "1234");

        mockIpvSessionItemAndTimeout(ProcessJourneyStepStates.CRI_FRAUD_STATE, environment);

        Map<String, Object> output = processJourneyStepHandler.handleRequest(input, mockContext);

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
    @ValueSource(strings = {"dev", "build", "staging", "integration", "production"})
    void shouldReturnCriErrorPageResponseIfFraudCriFails(String environment) {
        Map<String, String> input =
                Map.of(JOURNEY, ProcessJourneyStepEvents.ERROR, IPV_SESSION_ID, "1234");

        mockIpvSessionItemAndTimeout(ProcessJourneyStepStates.CRI_FRAUD_STATE, environment);

        Map<String, Object> output = processJourneyStepHandler.handleRequest(input, mockContext);

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
    @ValueSource(strings = {"dev", "build", "staging", "integration", "production"})
    void shouldReturnEvaluateGpg45ScoresWhenCriKbvState(String environment) {
        Map<String, String> input =
                Map.of(JOURNEY, ProcessJourneyStepEvents.JOURNEY_NEXT, IPV_SESSION_ID, "1234");

        mockIpvSessionItemAndTimeout(ProcessJourneyStepStates.CRI_KBV_STATE, environment);

        Map<String, Object> output = processJourneyStepHandler.handleRequest(input, mockContext);

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
    @ValueSource(strings = {"dev", "build", "staging", "integration", "production"})
    void shouldReturnCriErrorPageResponseIfKbvCriErrors(String environment) {
        Map<String, String> input =
                Map.of(JOURNEY, ProcessJourneyStepEvents.ERROR, IPV_SESSION_ID, "1234");

        mockIpvSessionItemAndTimeout(ProcessJourneyStepStates.CRI_KBV_STATE, environment);

        Map<String, Object> output = processJourneyStepHandler.handleRequest(input, mockContext);

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
    @ValueSource(strings = {"dev", "build", "staging", "integration", "production"})
    void shouldReturnEndSessionJourneyResponseWhenRequired(String environment) {
        Map<String, String> input =
                Map.of(JOURNEY, ProcessJourneyStepEvents.JOURNEY_NEXT, IPV_SESSION_ID, "1234");

        mockIpvSessionItemAndTimeout(ProcessJourneyStepStates.IPV_SUCCESS_PAGE_STATE, environment);

        Map<String, Object> output = processJourneyStepHandler.handleRequest(input, mockContext);

        ArgumentCaptor<IpvSessionItem> sessionArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(mockIpvSessionService).updateIpvSession(sessionArgumentCaptor.capture());
        assertEquals(
                ProcessJourneyStepStates.END_STATE,
                sessionArgumentCaptor.getValue().getUserState());

        assertEquals("/journey/build-client-oauth-response", output.get("journey"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"dev", "build", "staging", "integration", "production"})
    void shouldReturnDebugEvaluateGpg45ScoresJourneyWhenRequired(String environment) {
        Map<String, String> input =
                Map.of(JOURNEY, ProcessJourneyStepEvents.JOURNEY_NEXT, IPV_SESSION_ID, "1234");

        mockIpvSessionItemAndTimeout(ProcessJourneyStepStates.DEBUG_PAGE_STATE, environment);

        Map<String, Object> output = processJourneyStepHandler.handleRequest(input, mockContext);

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
    @ValueSource(strings = {"dev", "build", "staging", "integration", "production"})
    void shouldReturnPYITechnicalPageIfErrorOccursOnDebugJourney(String environment) {
        Map<String, String> input =
                Map.of(JOURNEY, ProcessJourneyStepEvents.ERROR, IPV_SESSION_ID, "1234");

        mockIpvSessionItemAndTimeout(ProcessJourneyStepStates.DEBUG_PAGE_STATE, environment);

        Map<String, Object> output = processJourneyStepHandler.handleRequest(input, mockContext);

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
    @ValueSource(strings = {"dev", "build", "staging", "integration", "production"})
    void shouldReturnPYINoMatchPageIfAccessDeniedOccursOnDebugJourney(String environment) {
        Map<String, String> input =
                Map.of(JOURNEY, ProcessJourneyStepEvents.ACCESS_DENIED, IPV_SESSION_ID, "1234");

        mockIpvSessionItemAndTimeout(ProcessJourneyStepStates.DEBUG_PAGE_STATE, environment);

        Map<String, Object> output = processJourneyStepHandler.handleRequest(input, mockContext);

        ArgumentCaptor<IpvSessionItem> sessionArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(mockIpvSessionService).updateIpvSession(sessionArgumentCaptor.capture());
        assertEquals(
                ProcessJourneyStepStates.PYI_NO_MATCH_STATE,
                sessionArgumentCaptor.getValue().getUserState());

        assertEquals(ProcessJourneyStepPages.PYI_NO_MATCH_PAGE, output.get("page"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"dev", "build", "staging", "integration", "production"})
    void shouldReturnErrorPageResponseWhenRequired(String environment) {
        Map<String, String> input =
                Map.of(JOURNEY, ProcessJourneyStepEvents.JOURNEY_NEXT, IPV_SESSION_ID, "1234");

        mockIpvSessionItemAndTimeout(ProcessJourneyStepStates.CRI_ERROR_STATE, environment);

        Map<String, Object> output = processJourneyStepHandler.handleRequest(input, mockContext);

        ArgumentCaptor<IpvSessionItem> sessionArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(mockIpvSessionService).updateIpvSession(sessionArgumentCaptor.capture());
        assertEquals(
                ProcessJourneyStepStates.END_STATE,
                sessionArgumentCaptor.getValue().getUserState());

        assertEquals("/journey/build-client-oauth-response", output.get("journey"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"dev", "build", "staging", "integration", "production"})
    void shouldReturnPYINoMatchPageIfCriStateReceivesAccessDenied(String environment) {
        Map<String, String> input =
                Map.of(JOURNEY, ProcessJourneyStepEvents.ACCESS_DENIED, IPV_SESSION_ID, "1234");

        mockIpvSessionItemAndTimeout(ProcessJourneyStepStates.CRI_UK_PASSPORT_STATE, environment);

        Map<String, Object> output = processJourneyStepHandler.handleRequest(input, mockContext);

        ArgumentCaptor<IpvSessionItem> sessionArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(mockIpvSessionService).updateIpvSession(sessionArgumentCaptor.capture());
        assertEquals(
                ProcessJourneyStepStates.PYI_NO_MATCH_STATE,
                sessionArgumentCaptor.getValue().getUserState());

        assertEquals(ProcessJourneyStepPages.PYI_NO_MATCH_PAGE, output.get("page"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"dev", "build", "staging", "integration", "production"})
    void shouldReturnPYITechnicalPageIfCriStateReceivesError(String environment) {
        Map<String, String> input =
                Map.of(JOURNEY, ProcessJourneyStepEvents.ERROR, IPV_SESSION_ID, "1234");

        mockIpvSessionItemAndTimeout(ProcessJourneyStepStates.CRI_FRAUD_STATE, environment);

        Map<String, Object> output = processJourneyStepHandler.handleRequest(input, mockContext);

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
    @ValueSource(strings = {"dev", "build", "staging", "integration", "production"})
    void shouldReturnPyiNoMatchPageIfInSelectCRIStateAndReturnsPyiNoMatchJourney(
            String environment) {
        Map<String, String> input =
                Map.of(JOURNEY, ProcessJourneyStepPages.PYI_NO_MATCH_PAGE, IPV_SESSION_ID, "1234");

        mockIpvSessionItemAndTimeout(ProcessJourneyStepStates.SELECT_CRI_STATE, environment);

        Map<String, Object> output = processJourneyStepHandler.handleRequest(input, mockContext);

        ArgumentCaptor<IpvSessionItem> sessionArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(mockIpvSessionService).updateIpvSession(sessionArgumentCaptor.capture());
        assertEquals(
                ProcessJourneyStepStates.PYI_NO_MATCH_STATE,
                sessionArgumentCaptor.getValue().getUserState());

        assertEquals(ProcessJourneyStepPages.PYI_NO_MATCH_PAGE, output.get("page"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"dev", "build", "staging", "integration", "production"})
    void shouldReturnPYITechnicalErrorIfSelectCRIReturnsFail(String environment) {
        Map<String, String> input =
                Map.of(JOURNEY, ProcessJourneyStepEvents.FAIL, IPV_SESSION_ID, "1234");

        mockIpvSessionItemAndTimeout(ProcessJourneyStepStates.SELECT_CRI_STATE, environment);

        Map<String, Object> output = processJourneyStepHandler.handleRequest(input, mockContext);

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
    @ValueSource(strings = {"dev", "build", "staging", "integration", "production"})
    void shouldReturnEvaluateGpg45ScoresJourneyIfInDcmawStateReturnsAccessDeniedResponse(
            String environment) {
        Map<String, String> input =
                Map.of(JOURNEY, ProcessJourneyStepEvents.ACCESS_DENIED, IPV_SESSION_ID, "1234");

        mockIpvSessionItemAndTimeout(ProcessJourneyStepStates.CRI_DCMAW_STATE, environment);

        Map<String, Object> output = processJourneyStepHandler.handleRequest(input, mockContext);

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
    @ValueSource(strings = {"dev", "build", "staging", "integration", "production"})
    void shouldReturnErrorPageIfSessionHasExpired(String environment) {
        Map<String, String> input =
                Map.of(JOURNEY, ProcessJourneyStepEvents.JOURNEY_NEXT, IPV_SESSION_ID, "1234");

        IpvSessionItem ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setIpvSessionId(SecureTokenHelper.generate());
        ipvSessionItem.setCreationDateTime(Instant.now().minusSeconds(100).toString());
        ipvSessionItem.setUserState(ProcessJourneyStepStates.CRI_UK_PASSPORT_STATE);
        ipvSessionItem.setClientSessionDetails(clientSessionDetailsDto);
        ipvSessionItem.setJourneyType(IpvJourneyTypes.IPV_CORE_MAIN_JOURNEY);

        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);
        when(mockConfigService.getSsmParameter(BACKEND_SESSION_TIMEOUT)).thenReturn("99");
        when(mockConfigService.getSsmParameter(BACKEND_SESSION_TIMEOUT)).thenReturn("99");
        when(mockConfigService.getEnvironmentVariable(EnvironmentVariable.ENVIRONMENT))
                .thenReturn(environment);
        when(mockIpvSessionService.getIpvSession("1234")).thenReturn(ipvSessionItem);

        Map<String, Object> output = processJourneyStepHandler.handleRequest(input, mockContext);

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

        assertEquals(ProcessJourneyStepPages.PYI_TECHNICAL_ERROR_PAGE, output.get("page"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"dev", "build", "staging", "integration", "production"})
    void shouldReturnSessionEndJourneyIfStateIsSessionTimeout(String environment) {
        Map<String, String> input =
                Map.of(JOURNEY, ProcessJourneyStepEvents.JOURNEY_NEXT, IPV_SESSION_ID, "1234");

        IpvSessionItem ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setIpvSessionId(SecureTokenHelper.generate());
        ipvSessionItem.setCreationDateTime(Instant.now().minusSeconds(100).toString());
        ipvSessionItem.setUserState(ProcessJourneyStepStates.CORE_SESSION_TIMEOUT_STATE);
        ipvSessionItem.setClientSessionDetails(clientSessionDetailsDto);
        ipvSessionItem.setJourneyType(IpvJourneyTypes.IPV_CORE_MAIN_JOURNEY);

        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);
        when(mockIpvSessionService.getIpvSession("1234")).thenReturn(ipvSessionItem);
        when(mockConfigService.getEnvironmentVariable(EnvironmentVariable.ENVIRONMENT))
                .thenReturn(environment);

        Map<String, Object> output = processJourneyStepHandler.handleRequest(input, mockContext);

        ArgumentCaptor<IpvSessionItem> sessionArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(mockIpvSessionService).updateIpvSession(sessionArgumentCaptor.capture());
        assertEquals(
                ProcessJourneyStepStates.END_STATE,
                sessionArgumentCaptor.getValue().getUserState());

        assertEquals("/journey/build-client-oauth-response", output.get("journey"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"dev", "build", "staging", "integration", "production"})
    void shouldClearOauthSessionIfItExists(String environment) {
        Map<String, String> input =
                Map.of(JOURNEY, ProcessJourneyStepEvents.JOURNEY_NEXT, IPV_SESSION_ID, "1234");

        IpvSessionItem ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setIpvSessionId(SecureTokenHelper.generate());
        ipvSessionItem.setCriOAuthSessionId(SecureTokenHelper.generate());
        ipvSessionItem.setCreationDateTime(Instant.now().toString());
        ipvSessionItem.setUserState(ProcessJourneyStepStates.IPV_IDENTITY_START_PAGE_STATE);
        ipvSessionItem.setClientSessionDetails(clientSessionDetailsDto);
        ipvSessionItem.setJourneyType(IpvJourneyTypes.IPV_CORE_MAIN_JOURNEY);
        ipvSessionItem.setCredentialIssuerSessionDetails(
                new CredentialIssuerSessionDetailsDto("some-cri", "some-state"));

        when(mockConfigService.getSsmParameter(BACKEND_SESSION_TIMEOUT)).thenReturn("7200");
        when(mockConfigService.getEnvironmentVariable(EnvironmentVariable.ENVIRONMENT))
                .thenReturn(environment);
        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);
        processJourneyStepHandler.handleRequest(input, mockContext);

        ArgumentCaptor<IpvSessionItem> sessionArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(mockIpvSessionService).updateIpvSession(sessionArgumentCaptor.capture());
        assertNotNull(sessionArgumentCaptor.getValue().getCriOAuthSessionId());
    }

    private void mockIpvSessionItemAndTimeout(String validateOauthCallback, String environment) {
        IpvSessionItem ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setIpvSessionId(SecureTokenHelper.generate());
        ipvSessionItem.setCreationDateTime(Instant.now().toString());
        ipvSessionItem.setUserState(validateOauthCallback);
        ipvSessionItem.setClientSessionDetails(clientSessionDetailsDto);
        ipvSessionItem.setJourneyType(IpvJourneyTypes.IPV_CORE_MAIN_JOURNEY);

        when(mockConfigService.getSsmParameter(BACKEND_SESSION_TIMEOUT)).thenReturn("7200");
        when(mockConfigService.getEnvironmentVariable(EnvironmentVariable.ENVIRONMENT))
                .thenReturn(environment);
        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);
    }
}
