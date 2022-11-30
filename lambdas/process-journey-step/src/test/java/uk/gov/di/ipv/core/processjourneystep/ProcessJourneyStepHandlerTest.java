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
import uk.gov.di.ipv.core.library.helpers.SecureTokenHelper;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.ConfigurationService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;

import java.time.Instant;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.BACKEND_SESSION_TIMEOUT;
import static uk.gov.di.ipv.core.library.helpers.StepFunctionHelpers.CODE;
import static uk.gov.di.ipv.core.library.helpers.StepFunctionHelpers.IPV_SESSION_ID;
import static uk.gov.di.ipv.core.library.helpers.StepFunctionHelpers.JOURNEY;
import static uk.gov.di.ipv.core.library.helpers.StepFunctionHelpers.MESSAGE;
import static uk.gov.di.ipv.core.library.helpers.StepFunctionHelpers.STATUS_CODE;

@ExtendWith(MockitoExtension.class)
class ProcessJourneyStepHandlerTest {
    private static final String NEXT = "/journey/next";
    private static final String ERROR = "error";
    public static final String REUSE = "/journey/reuse";
    private static final String ACCESS_DENIED = "access-denied";
    private static final String INVALID_STEP = "invalid-step";

    private static final String INITIAL_IPV_JOURNEY_STATE = "INITIAL_IPV_JOURNEY";
    private static final String IPV_IDENTITY_START_PAGE_STATE = "IPV_IDENTITY_START_PAGE";
    private static final String SELECT_CRI_STATE = "SELECT_CRI";
    private static final String CRI_UK_PASSPORT_STATE = "CRI_UK_PASSPORT";
    private static final String CRI_ADDRESS_STATE = "CRI_ADDRESS";
    private static final String CRI_FRAUD_STATE = "CRI_FRAUD";
    private static final String CRI_KBV_STATE = "CRI_KBV";
    private static final String CRI_DCMAW_STATE = "CRI_DCMAW";
    private static final String CRI_ERROR_STATE = "CRI_ERROR";
    private static final String EVALUATE_GPG45_SCORES = "EVALUATE_GPG45_SCORES";
    private static final String PRE_KBV_TRANSITION_PAGE_STATE = "PRE_KBV_TRANSITION_PAGE";
    private static final String IPV_SUCCESS_PAGE_STATE = "IPV_SUCCESS_PAGE";
    private static final String DEBUG_PAGE_STATE = "DEBUG_PAGE";
    private static final String DEBUG_EVALUATE_GPG45_SCORES = "DEBUG_EVALUATE_GPG45_SCORES";
    private static final String PYI_NO_MATCH_STATE = "PYI_NO_MATCH";
    private static final String CORE_SESSION_TIMEOUT_STATE = "CORE_SESSION_TIMEOUT";
    public static final String END_STATE = "END";

    private static final String IPV_IDENTITY_START_PAGE = "page-ipv-identity-start";
    private static final String PYI_TECHNICAL_ERROR_PAGE = "pyi-technical";
    private static final String PYI_NO_MATCH_PAGE = "pyi-no-match";
    private static final String PRE_KBV_TRANSITION_PAGE = "page-pre-kbv-transition";
    public static final String JOURNEY_EVALUATE_GPG_45_SCORES = "/journey/evaluate-gpg45-scores";
    public static final String CHECK_EXISTING_IDENTITY_STATE = "CHECK_EXISTING_IDENTITY";
    public static final String JOURNEY_CHECK_EXISTING_IDENTITY = "/journey/check-existing-identity";
    public static final String IPV_IDENTITY_REUSE_PAGE_STATE = "IPV_IDENTITY_REUSE_PAGE";
    public static final String IPV_IDENTITY_REUSE_PAGE = "page-ipv-reuse";
    @Mock private Context mockContext;
    @Mock private IpvSessionService mockIpvSessionService;
    @Mock private ConfigurationService mockConfigurationService;
    @Mock private IpvSessionItem mockIpvSessionItem;

    private ProcessJourneyStepHandler processJourneyStepHandler;
    private ClientSessionDetailsDto clientSessionDetailsDto;

    @BeforeEach
    void setUp() {
        processJourneyStepHandler =
                new ProcessJourneyStepHandler(mockIpvSessionService, mockConfigurationService);
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
        Map<String, String> input = Map.of(JOURNEY, NEXT);

        Map<String, Object> output = processJourneyStepHandler.handleRequest(input, mockContext);

        assertEquals(HttpStatus.SC_BAD_REQUEST, output.get(STATUS_CODE));
        assertEquals(ErrorResponse.MISSING_IPV_SESSION_ID.getCode(), output.get(CODE));
        assertEquals(ErrorResponse.MISSING_IPV_SESSION_ID.getMessage(), output.get(MESSAGE));
    }

    @ParameterizedTest
    @ValueSource(strings = {"dev", "build", "staging", "integration", "production"})
    void shouldReturn400WhenInvalidSessionIdProvided() {
        Map<String, String> input = Map.of(JOURNEY, NEXT, IPV_SESSION_ID, "1234");

        when(mockIpvSessionService.getIpvSession("1234")).thenReturn(null);

        Map<String, Object> output = processJourneyStepHandler.handleRequest(input, mockContext);

        assertEquals(HttpStatus.SC_BAD_REQUEST, output.get(STATUS_CODE));
        assertEquals(ErrorResponse.INVALID_SESSION_ID.getCode(), output.get(CODE));
        assertEquals(ErrorResponse.INVALID_SESSION_ID.getMessage(), output.get(MESSAGE));
    }

    @ParameterizedTest
    @ValueSource(strings = {"dev", "build", "staging", "integration", "production"})
    void shouldReturn500WhenUnknownJourneyEngineStepProvided(String environment) {
        Map<String, String> input = Map.of(JOURNEY, INVALID_STEP, IPV_SESSION_ID, "1234");

        mockIpvSessionItemAndTimeout(INITIAL_IPV_JOURNEY_STATE, environment);

        Map<String, Object> output = processJourneyStepHandler.handleRequest(input, mockContext);

        assertEquals(HttpStatus.SC_INTERNAL_SERVER_ERROR, output.get(STATUS_CODE));
        assertEquals(ErrorResponse.FAILED_JOURNEY_ENGINE_STEP.getCode(), output.get(CODE));
        assertEquals(ErrorResponse.FAILED_JOURNEY_ENGINE_STEP.getMessage(), output.get(MESSAGE));
    }

    @ParameterizedTest
    @ValueSource(strings = {"dev", "build", "staging", "integration", "production"})
    void shouldReturn500WhenUserIsInUnknownState(String environment) {
        Map<String, String> input = Map.of(JOURNEY, INVALID_STEP, IPV_SESSION_ID, "1234");

        mockIpvSessionItemAndTimeout("INVALID-STATE", environment);

        Map<String, Object> output = processJourneyStepHandler.handleRequest(input, mockContext);

        assertEquals(HttpStatus.SC_INTERNAL_SERVER_ERROR, output.get(STATUS_CODE));
        assertEquals(ErrorResponse.FAILED_JOURNEY_ENGINE_STEP.getCode(), output.get(CODE));
        assertEquals(ErrorResponse.FAILED_JOURNEY_ENGINE_STEP.getMessage(), output.get(MESSAGE));
    }

    @ParameterizedTest
    @ValueSource(strings = {"dev", "build", "staging"})
    void shouldReturnCheckExistingIdentityResponseWhenRequired(String environment) {
        Map<String, String> input = Map.of(JOURNEY, NEXT, IPV_SESSION_ID, "1234");

        mockIpvSessionItemAndTimeout(IPV_IDENTITY_START_PAGE_STATE, environment);

        when(mockConfigurationService.getEnvironmentVariable(EnvironmentVariable.ENVIRONMENT))
                .thenReturn(environment);

        Map<String, Object> output = processJourneyStepHandler.handleRequest(input, mockContext);

        assertEquals(JOURNEY_CHECK_EXISTING_IDENTITY, output.get("journey"));

        ArgumentCaptor<IpvSessionItem> sessionArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(mockIpvSessionService).updateIpvSession(sessionArgumentCaptor.capture());
        assertEquals(
                CHECK_EXISTING_IDENTITY_STATE, sessionArgumentCaptor.getValue().getUserState());
    }

    @ParameterizedTest
    @ValueSource(strings = {"dev", "build", "staging", "integration", "production"})
    void shouldReturnIdentityStartPageResponseWhenRequired(String environment) {
        Map<String, String> input = Map.of(JOURNEY, NEXT, IPV_SESSION_ID, "1234");

        mockIpvSessionItemAndTimeout(INITIAL_IPV_JOURNEY_STATE, environment);

        Map<String, Object> output = processJourneyStepHandler.handleRequest(input, mockContext);

        assertEquals(IPV_IDENTITY_START_PAGE, output.get("page"));

        ArgumentCaptor<IpvSessionItem> sessionArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(mockIpvSessionService).updateIpvSession(sessionArgumentCaptor.capture());
        assertEquals(
                IPV_IDENTITY_START_PAGE_STATE, sessionArgumentCaptor.getValue().getUserState());
    }

    @ParameterizedTest
    @ValueSource(strings = {"dev", "build", "staging"})
    void shouldReturnIdentityReusePageResponseWhenRequired(String environment) {
        Map<String, String> input = Map.of(JOURNEY, REUSE, IPV_SESSION_ID, "1234");

        mockIpvSessionItemAndTimeout(CHECK_EXISTING_IDENTITY_STATE, environment);

        Map<String, Object> output = processJourneyStepHandler.handleRequest(input, mockContext);

        assertEquals(IPV_IDENTITY_REUSE_PAGE, output.get("page"));

        ArgumentCaptor<IpvSessionItem> sessionArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(mockIpvSessionService).updateIpvSession(sessionArgumentCaptor.capture());
        assertEquals(
                IPV_IDENTITY_REUSE_PAGE_STATE, sessionArgumentCaptor.getValue().getUserState());
    }

    @ParameterizedTest
    @ValueSource(strings = {"dev", "build", "staging"})
    void shouldReturnEvaluateGpg45ScoresWhenIpvIdentityStartPageState(String environment) {
        Map<String, String> input = Map.of(JOURNEY, NEXT, IPV_SESSION_ID, "1234");

        mockIpvSessionItemAndTimeout(CHECK_EXISTING_IDENTITY_STATE, environment);

        Map<String, Object> output = processJourneyStepHandler.handleRequest(input, mockContext);

        ArgumentCaptor<IpvSessionItem> sessionArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(mockIpvSessionService).updateIpvSession(sessionArgumentCaptor.capture());
        assertEquals(EVALUATE_GPG45_SCORES, sessionArgumentCaptor.getValue().getUserState());

        assertEquals(JOURNEY_EVALUATE_GPG_45_SCORES, output.get("journey"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"dev", "build", "staging", "integration", "production"})
    void shouldReturnEvaluateGpg45ScoresWhenCriUkPassportState(String environment) {
        Map<String, String> input = Map.of(JOURNEY, NEXT, IPV_SESSION_ID, "1234");

        mockIpvSessionItemAndTimeout(CRI_UK_PASSPORT_STATE, environment);

        Map<String, Object> output = processJourneyStepHandler.handleRequest(input, mockContext);

        ArgumentCaptor<IpvSessionItem> sessionArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(mockIpvSessionService).updateIpvSession(sessionArgumentCaptor.capture());
        assertEquals(EVALUATE_GPG45_SCORES, sessionArgumentCaptor.getValue().getUserState());

        assertEquals(JOURNEY_EVALUATE_GPG_45_SCORES, output.get("journey"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"dev", "build", "staging", "integration", "production"})
    void shouldReturnCriErrorPageResponseIfPassportCriErrors(String environment) {
        Map<String, String> input = Map.of(JOURNEY, ERROR, IPV_SESSION_ID, "1234");

        mockIpvSessionItemAndTimeout(CRI_UK_PASSPORT_STATE, environment);

        Map<String, Object> output = processJourneyStepHandler.handleRequest(input, mockContext);

        ArgumentCaptor<IpvSessionItem> sessionArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(mockIpvSessionService).updateIpvSession(sessionArgumentCaptor.capture());
        assertEquals(CRI_ERROR_STATE, sessionArgumentCaptor.getValue().getUserState());

        assertEquals(PYI_TECHNICAL_ERROR_PAGE, output.get("page"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"dev", "build", "staging", "integration", "production"})
    void shouldReturnEvaluateGpg45ScoresWhenCriAddressState(String environment) {
        Map<String, String> input = Map.of(JOURNEY, NEXT, IPV_SESSION_ID, "1234");

        mockIpvSessionItemAndTimeout(CRI_ADDRESS_STATE, environment);

        Map<String, Object> output = processJourneyStepHandler.handleRequest(input, mockContext);

        ArgumentCaptor<IpvSessionItem> sessionArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(mockIpvSessionService).updateIpvSession(sessionArgumentCaptor.capture());
        assertEquals(EVALUATE_GPG45_SCORES, sessionArgumentCaptor.getValue().getUserState());

        assertEquals(JOURNEY_EVALUATE_GPG_45_SCORES, output.get("journey"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"dev", "build", "staging", "integration", "production"})
    void shouldReturnCriErrorPageResponseIfAddressCriErrors(String environment) {
        Map<String, String> input = Map.of(JOURNEY, ERROR, IPV_SESSION_ID, "1234");

        mockIpvSessionItemAndTimeout(CRI_ADDRESS_STATE, environment);

        Map<String, Object> output = processJourneyStepHandler.handleRequest(input, mockContext);

        ArgumentCaptor<IpvSessionItem> sessionArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(mockIpvSessionService).updateIpvSession(sessionArgumentCaptor.capture());
        assertEquals(CRI_ERROR_STATE, sessionArgumentCaptor.getValue().getUserState());

        assertEquals(PYI_TECHNICAL_ERROR_PAGE, output.get("page"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"dev", "build", "staging", "integration", "production"})
    void shouldReturnEvaluateGpg45ScoresWhenCriFraudState(String environment) {
        Map<String, String> input = Map.of(JOURNEY, NEXT, IPV_SESSION_ID, "1234");

        mockIpvSessionItemAndTimeout(CRI_FRAUD_STATE, environment);

        Map<String, Object> output = processJourneyStepHandler.handleRequest(input, mockContext);

        ArgumentCaptor<IpvSessionItem> sessionArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(mockIpvSessionService).updateIpvSession(sessionArgumentCaptor.capture());
        assertEquals(EVALUATE_GPG45_SCORES, sessionArgumentCaptor.getValue().getUserState());

        assertEquals(JOURNEY_EVALUATE_GPG_45_SCORES, output.get("journey"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"staging", "integration", "production"})
    void shouldReturnPreKbvTransitionPageResponseWhenRequired(String environment) {
        Map<String, String> input =
                Map.of(
                        JOURNEY, "kbv",
                        IPV_SESSION_ID, "1234");

        mockIpvSessionItemAndTimeout(SELECT_CRI_STATE, environment);

        Map<String, Object> output = processJourneyStepHandler.handleRequest(input, mockContext);

        ArgumentCaptor<IpvSessionItem> sessionArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(mockIpvSessionService).updateIpvSession(sessionArgumentCaptor.capture());
        assertEquals(
                PRE_KBV_TRANSITION_PAGE_STATE, sessionArgumentCaptor.getValue().getUserState());

        assertEquals(PRE_KBV_TRANSITION_PAGE, output.get("page"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"staging", "integration", "production"})
    void shouldReturnCriKbvJourneyResponseWhenRequired(String environment) {
        Map<String, String> input = Map.of(JOURNEY, NEXT, IPV_SESSION_ID, "1234");

        mockIpvSessionItemAndTimeout(PRE_KBV_TRANSITION_PAGE_STATE, environment);

        Map<String, Object> output = processJourneyStepHandler.handleRequest(input, mockContext);

        ArgumentCaptor<IpvSessionItem> sessionArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(mockIpvSessionService).updateIpvSession(sessionArgumentCaptor.capture());
        assertEquals(CRI_KBV_STATE, sessionArgumentCaptor.getValue().getUserState());

        assertEquals("/journey/cri/build-oauth-request/kbv", output.get("journey"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"dev", "build", "staging", "integration", "production"})
    void shouldReturnCriErrorPageResponseIfFraudCriFails(String environment) {
        Map<String, String> input = Map.of(JOURNEY, ERROR, IPV_SESSION_ID, "1234");

        mockIpvSessionItemAndTimeout(CRI_FRAUD_STATE, environment);

        Map<String, Object> output = processJourneyStepHandler.handleRequest(input, mockContext);

        ArgumentCaptor<IpvSessionItem> sessionArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(mockIpvSessionService).updateIpvSession(sessionArgumentCaptor.capture());
        assertEquals(CRI_ERROR_STATE, sessionArgumentCaptor.getValue().getUserState());

        assertEquals(PYI_TECHNICAL_ERROR_PAGE, output.get("page"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"dev", "build", "staging", "integration", "production"})
    void shouldReturnEvaluateGpg45ScoresWhenCriKbvState(String environment) {
        Map<String, String> input = Map.of(JOURNEY, NEXT, IPV_SESSION_ID, "1234");

        mockIpvSessionItemAndTimeout(CRI_KBV_STATE, environment);

        Map<String, Object> output = processJourneyStepHandler.handleRequest(input, mockContext);

        ArgumentCaptor<IpvSessionItem> sessionArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(mockIpvSessionService).updateIpvSession(sessionArgumentCaptor.capture());
        assertEquals(EVALUATE_GPG45_SCORES, sessionArgumentCaptor.getValue().getUserState());

        assertEquals(JOURNEY_EVALUATE_GPG_45_SCORES, output.get("journey"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"dev", "build", "staging", "integration", "production"})
    void shouldReturnCriErrorPageResponseIfKbvCriErrors(String environment) {
        Map<String, String> input = Map.of(JOURNEY, ERROR, IPV_SESSION_ID, "1234");

        mockIpvSessionItemAndTimeout(CRI_KBV_STATE, environment);

        Map<String, Object> output = processJourneyStepHandler.handleRequest(input, mockContext);

        ArgumentCaptor<IpvSessionItem> sessionArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(mockIpvSessionService).updateIpvSession(sessionArgumentCaptor.capture());
        assertEquals(CRI_ERROR_STATE, sessionArgumentCaptor.getValue().getUserState());

        assertEquals(PYI_TECHNICAL_ERROR_PAGE, output.get("page"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"dev", "build", "staging", "integration", "production"})
    void shouldReturnEndSessionJourneyResponseWhenRequired(String environment) {
        Map<String, String> input = Map.of(JOURNEY, NEXT, IPV_SESSION_ID, "1234");

        mockIpvSessionItemAndTimeout(IPV_SUCCESS_PAGE_STATE, environment);

        Map<String, Object> output = processJourneyStepHandler.handleRequest(input, mockContext);

        ArgumentCaptor<IpvSessionItem> sessionArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(mockIpvSessionService).updateIpvSession(sessionArgumentCaptor.capture());
        assertEquals(END_STATE, sessionArgumentCaptor.getValue().getUserState());

        assertEquals("/journey/build-client-oauth-response", output.get("journey"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"dev", "build", "staging", "integration", "production"})
    void shouldReturnDebugEvaluateGpg45ScoresJourneyWhenRequired(String environment) {
        Map<String, String> input = Map.of(JOURNEY, NEXT, IPV_SESSION_ID, "1234");

        mockIpvSessionItemAndTimeout(DEBUG_PAGE_STATE, environment);

        Map<String, Object> output = processJourneyStepHandler.handleRequest(input, mockContext);

        ArgumentCaptor<IpvSessionItem> sessionArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(mockIpvSessionService).updateIpvSession(sessionArgumentCaptor.capture());
        assertEquals(DEBUG_EVALUATE_GPG45_SCORES, sessionArgumentCaptor.getValue().getUserState());

        assertEquals(JOURNEY_EVALUATE_GPG_45_SCORES, output.get("journey"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"dev", "build", "staging", "integration", "production"})
    void shouldReturnPYITechnicalPageIfErrorOccursOnDebugJourney(String environment) {
        Map<String, String> input = Map.of(JOURNEY, ERROR, IPV_SESSION_ID, "1234");

        mockIpvSessionItemAndTimeout(DEBUG_PAGE_STATE, environment);

        Map<String, Object> output = processJourneyStepHandler.handleRequest(input, mockContext);

        ArgumentCaptor<IpvSessionItem> sessionArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(mockIpvSessionService).updateIpvSession(sessionArgumentCaptor.capture());
        assertEquals(CRI_ERROR_STATE, sessionArgumentCaptor.getValue().getUserState());

        assertEquals(PYI_TECHNICAL_ERROR_PAGE, output.get("page"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"dev", "build", "staging", "integration", "production"})
    void shouldReturnPYINoMatchPageIfAccessDeniedOccursOnDebugJourney(String environment) {
        Map<String, String> input = Map.of(JOURNEY, ACCESS_DENIED, IPV_SESSION_ID, "1234");

        mockIpvSessionItemAndTimeout(DEBUG_PAGE_STATE, environment);

        Map<String, Object> output = processJourneyStepHandler.handleRequest(input, mockContext);

        ArgumentCaptor<IpvSessionItem> sessionArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(mockIpvSessionService).updateIpvSession(sessionArgumentCaptor.capture());
        assertEquals(PYI_NO_MATCH_STATE, sessionArgumentCaptor.getValue().getUserState());

        assertEquals(PYI_NO_MATCH_PAGE, output.get("page"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"dev", "build", "staging", "integration", "production"})
    void shouldReturnErrorPageResponseWhenRequired(String environment) {
        Map<String, String> input = Map.of(JOURNEY, NEXT, IPV_SESSION_ID, "1234");

        mockIpvSessionItemAndTimeout(CRI_ERROR_STATE, environment);

        Map<String, Object> output = processJourneyStepHandler.handleRequest(input, mockContext);

        ArgumentCaptor<IpvSessionItem> sessionArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(mockIpvSessionService).updateIpvSession(sessionArgumentCaptor.capture());
        assertEquals(END_STATE, sessionArgumentCaptor.getValue().getUserState());

        assertEquals("/journey/build-client-oauth-response", output.get("journey"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"dev", "build", "staging", "integration", "production"})
    void shouldReturnPYINoMatchPageIfCriStateReceivesAccessDenied(String environment) {
        Map<String, String> input = Map.of(JOURNEY, ACCESS_DENIED, IPV_SESSION_ID, "1234");

        mockIpvSessionItemAndTimeout(CRI_UK_PASSPORT_STATE, environment);

        Map<String, Object> output = processJourneyStepHandler.handleRequest(input, mockContext);

        ArgumentCaptor<IpvSessionItem> sessionArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(mockIpvSessionService).updateIpvSession(sessionArgumentCaptor.capture());
        assertEquals(PYI_NO_MATCH_STATE, sessionArgumentCaptor.getValue().getUserState());

        assertEquals(PYI_NO_MATCH_PAGE, output.get("page"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"dev", "build", "staging", "integration", "production"})
    void shouldReturnPYITechnicalPageIfCriStateReceivesError(String environment) {
        Map<String, String> input = Map.of(JOURNEY, ERROR, IPV_SESSION_ID, "1234");

        mockIpvSessionItemAndTimeout(CRI_FRAUD_STATE, environment);

        Map<String, Object> output = processJourneyStepHandler.handleRequest(input, mockContext);

        ArgumentCaptor<IpvSessionItem> sessionArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(mockIpvSessionService).updateIpvSession(sessionArgumentCaptor.capture());
        assertEquals(CRI_ERROR_STATE, sessionArgumentCaptor.getValue().getUserState());

        assertEquals(PYI_TECHNICAL_ERROR_PAGE, output.get("page"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"dev", "build", "staging", "integration", "production"})
    void shouldReturnPyiNoMatchPageIfInSelectCRIStateAndReturnsPyiNoMatchJourney(
            String environment) {
        Map<String, String> input = Map.of(JOURNEY, PYI_NO_MATCH_PAGE, IPV_SESSION_ID, "1234");

        mockIpvSessionItemAndTimeout(SELECT_CRI_STATE, environment);

        Map<String, Object> output = processJourneyStepHandler.handleRequest(input, mockContext);

        ArgumentCaptor<IpvSessionItem> sessionArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(mockIpvSessionService).updateIpvSession(sessionArgumentCaptor.capture());
        assertEquals(PYI_NO_MATCH_STATE, sessionArgumentCaptor.getValue().getUserState());

        assertEquals(PYI_NO_MATCH_PAGE, output.get("page"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"dev", "build", "staging", "integration", "production"})
    void shouldReturnEvaluateGpg45ScoresJourneyIfInDcmawStateReturnsAccessDeniedResponse(
            String environment) {
        Map<String, String> input = Map.of(JOURNEY, ACCESS_DENIED, IPV_SESSION_ID, "1234");

        mockIpvSessionItemAndTimeout(CRI_DCMAW_STATE, environment);

        Map<String, Object> output = processJourneyStepHandler.handleRequest(input, mockContext);

        ArgumentCaptor<IpvSessionItem> sessionArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(mockIpvSessionService).updateIpvSession(sessionArgumentCaptor.capture());
        assertEquals(EVALUATE_GPG45_SCORES, sessionArgumentCaptor.getValue().getUserState());

        assertEquals(JOURNEY_EVALUATE_GPG_45_SCORES, output.get("journey"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"dev", "build", "staging", "integration", "production"})
    void shouldReturnErrorPageIfSessionHasExpired(String environment) {
        Map<String, String> input = Map.of(JOURNEY, NEXT, IPV_SESSION_ID, "1234");

        IpvSessionItem ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setIpvSessionId(SecureTokenHelper.generate());
        ipvSessionItem.setCreationDateTime(Instant.now().minusSeconds(100).toString());
        ipvSessionItem.setUserState(CRI_UK_PASSPORT_STATE);
        ipvSessionItem.setClientSessionDetails(clientSessionDetailsDto);
        ipvSessionItem.setJourneyType(IpvJourneyTypes.IPV_CORE_MAIN_JOURNEY);

        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);
        when(mockConfigurationService.getSsmParameter(BACKEND_SESSION_TIMEOUT)).thenReturn("99");
        when(mockConfigurationService.getSsmParameter(BACKEND_SESSION_TIMEOUT)).thenReturn("99");
        when(mockConfigurationService.getEnvironmentVariable(EnvironmentVariable.ENVIRONMENT))
                .thenReturn(environment);
        when(mockIpvSessionService.getIpvSession("1234")).thenReturn(ipvSessionItem);

        Map<String, Object> output = processJourneyStepHandler.handleRequest(input, mockContext);

        ArgumentCaptor<IpvSessionItem> sessionArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(mockIpvSessionService).updateIpvSession(sessionArgumentCaptor.capture());

        IpvSessionItem capturedIpvSessionItem = sessionArgumentCaptor.getValue();
        assertEquals(CORE_SESSION_TIMEOUT_STATE, sessionArgumentCaptor.getValue().getUserState());
        assertEquals(OAuth2Error.ACCESS_DENIED.getCode(), capturedIpvSessionItem.getErrorCode());
        assertEquals(
                OAuth2Error.ACCESS_DENIED.getDescription(),
                capturedIpvSessionItem.getErrorDescription());

        assertEquals(PYI_TECHNICAL_ERROR_PAGE, output.get("page"));
    }

    @ParameterizedTest
    @ValueSource(strings = {"dev", "build", "staging", "integration", "production"})
    void shouldReturnSessionEndJourneyIfStateIsSessionTimeout(String environment) {
        Map<String, String> input = Map.of(JOURNEY, NEXT, IPV_SESSION_ID, "1234");

        IpvSessionItem ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setIpvSessionId(SecureTokenHelper.generate());
        ipvSessionItem.setCreationDateTime(Instant.now().minusSeconds(100).toString());
        ipvSessionItem.setUserState(CORE_SESSION_TIMEOUT_STATE);
        ipvSessionItem.setClientSessionDetails(clientSessionDetailsDto);
        ipvSessionItem.setJourneyType(IpvJourneyTypes.IPV_CORE_MAIN_JOURNEY);

        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);
        when(mockIpvSessionService.getIpvSession("1234")).thenReturn(ipvSessionItem);
        when(mockConfigurationService.getEnvironmentVariable(EnvironmentVariable.ENVIRONMENT))
                .thenReturn(environment);

        Map<String, Object> output = processJourneyStepHandler.handleRequest(input, mockContext);

        ArgumentCaptor<IpvSessionItem> sessionArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(mockIpvSessionService).updateIpvSession(sessionArgumentCaptor.capture());
        assertEquals(END_STATE, sessionArgumentCaptor.getValue().getUserState());

        assertEquals("/journey/build-client-oauth-response", output.get("journey"));
    }

    private void mockIpvSessionItemAndTimeout(String validateOauthCallback, String environment) {
        IpvSessionItem ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setIpvSessionId(SecureTokenHelper.generate());
        ipvSessionItem.setCreationDateTime(Instant.now().toString());
        ipvSessionItem.setUserState(validateOauthCallback);
        ipvSessionItem.setClientSessionDetails(clientSessionDetailsDto);
        ipvSessionItem.setJourneyType(IpvJourneyTypes.IPV_CORE_MAIN_JOURNEY);

        when(mockConfigurationService.getSsmParameter(BACKEND_SESSION_TIMEOUT)).thenReturn("7200");
        when(mockConfigurationService.getEnvironmentVariable(EnvironmentVariable.ENVIRONMENT))
                .thenReturn(environment);
        when(mockIpvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);
    }
}
