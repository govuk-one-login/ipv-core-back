package uk.gov.di.ipv.core.ciscoring;

import com.amazonaws.services.lambda.runtime.Context;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.http.HttpStatus;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.cimit.exception.CiRetrievalException;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.JourneyErrorResponse;
import uk.gov.di.ipv.core.library.domain.JourneyRequest;
import uk.gov.di.ipv.core.library.domain.JourneyResponse;
import uk.gov.di.ipv.core.library.domain.gpg45.Gpg45ProfileEvaluator;
import uk.gov.di.ipv.core.library.dto.VisitedCredentialIssuerDetailsDto;
import uk.gov.di.ipv.core.library.exceptions.ConfigException;
import uk.gov.di.ipv.core.library.exceptions.UnrecognisedCiException;
import uk.gov.di.ipv.core.library.helpers.SecureTokenHelper;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.CiMitService;
import uk.gov.di.ipv.core.library.service.ClientOAuthSessionDetailsService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.config.CoreFeatureFlag.USE_CONTRA_INDICATOR_VC;

@ExtendWith(MockitoExtension.class)
class CiScoringHandlerTest {
    private static final String USER_STATE_INITIAL_CI_SCORING = "INITIAL_CI_SCORING";
    private static final String TEST_SESSION_ID = "test-session-id";
    private static final String TEST_CLIENT_SOURCE_IP = "test-client-source-ip";
    private static final String TEST_USER_ID = "test-user-id";
    private static final String TEST_JOURNEY_ID = "test-journey-id";
    private static final String JOURNEY_ERROR = "/journey/error";
    private static final JourneyResponse JOURNEY_NEXT = new JourneyResponse("/journey/next");
    private static final String JOURNEY_PYI_NO_MATCH = "/journey/pyi-no-match";
    private static final String TEST_CLIENT_OAUTH_SESSION_ID = SecureTokenHelper.generate();
    private static final ObjectMapper mapper = new ObjectMapper();
    private static JourneyRequest request;
    @Mock private CiMitService ciMitService;
    @Mock private ClientOAuthSessionDetailsService clientOAuthSessionDetailsService;
    @Mock private ConfigService configService;
    @Mock private Context context;
    @Mock private Gpg45ProfileEvaluator gpg45ProfileEvaluator;
    @Mock private IpvSessionService ipvSessionService;
    @InjectMocks private CiScoringHandler ciScoringHandler;

    private IpvSessionItem ipvSessionItem;
    private ClientOAuthSessionItem clientOAuthSessionItem;

    @BeforeAll
    static void setUp() {
        request =
                JourneyRequest.builder()
                        .ipvSessionId(TEST_SESSION_ID)
                        .ipAddress(TEST_CLIENT_SOURCE_IP)
                        .build();
    }

    @BeforeEach
    void setUpEach() {
        ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setClientOAuthSessionId(TEST_CLIENT_OAUTH_SESSION_ID);
        ipvSessionItem.setIpvSessionId(TEST_SESSION_ID);
        ipvSessionItem.setVisitedCredentialIssuerDetails(
                List.of(
                        new VisitedCredentialIssuerDetailsDto(
                                "criId",
                                "https://review-a.integration.account.gov.uk",
                                true,
                                null)));

        clientOAuthSessionItem =
                ClientOAuthSessionItem.builder()
                        .clientOAuthSessionId(TEST_CLIENT_OAUTH_SESSION_ID)
                        .state("test-state")
                        .responseType("code")
                        .redirectUri("https://example.com/redirect")
                        .govukSigninJourneyId("test-journey-id")
                        .userId(TEST_USER_ID)
                        .clientId("test-client")
                        .govukSigninJourneyId(TEST_JOURNEY_ID)
                        .build();
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void shouldReturnJourneyNextIfNoBreachingCIs(boolean useContraIndicatorVC) throws Exception {
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(configService.enabled(USE_CONTRA_INDICATOR_VC)).thenReturn(useContraIndicatorVC);
        mockCiJourneyResponse(useContraIndicatorVC, Optional.empty(), false);
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        JourneyResponse response =
                toResponseClass(
                        ciScoringHandler.handleRequest(request, context), JourneyResponse.class);

        assertEquals(JOURNEY_NEXT.getJourney(), response.getJourney());
        verify(clientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void shouldReturnJourneyNoMatchJourneyResponseIfCiAreFoundOnVcs(boolean useContraIndicatorVC)
            throws Exception {
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(configService.enabled(USE_CONTRA_INDICATOR_VC)).thenReturn(useContraIndicatorVC);
        mockCiJourneyResponse(
                useContraIndicatorVC,
                Optional.of(new JourneyResponse(JOURNEY_PYI_NO_MATCH)),
                false);
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        JourneyResponse response =
                toResponseClass(
                        ciScoringHandler.handleRequest(request, context), JourneyResponse.class);

        assertEquals(JOURNEY_PYI_NO_MATCH, response.getJourney());
    }

    @Test
    void shouldReturn500IfFailedToRetrieveCisFromStorageSystem() throws Exception {
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(ciMitService.getCIs(anyString(), anyString(), anyString()))
                .thenThrow(CiRetrievalException.class);
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        JourneyErrorResponse response =
                toResponseClass(
                        ciScoringHandler.handleRequest(request, context),
                        JourneyErrorResponse.class);

        assertEquals(HttpStatus.SC_INTERNAL_SERVER_ERROR, response.getStatusCode());
        assertEquals(ErrorResponse.FAILED_TO_GET_STORED_CIS.getCode(), response.getCode());
        assertEquals(ErrorResponse.FAILED_TO_GET_STORED_CIS.getMessage(), response.getMessage());
        verify(clientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());
    }

    @ParameterizedTest
    @ValueSource(booleans = {true})
    void shouldReturn500IfFailedToGetCimitConfig(boolean useContraIndicatorVC) throws Exception {
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(configService.enabled(USE_CONTRA_INDICATOR_VC)).thenReturn(useContraIndicatorVC);
        mockCiJourneyResponseException(
                useContraIndicatorVC, new ConfigException("Failed to get cimit config"));

        JourneyErrorResponse response =
                toResponseClass(
                        ciScoringHandler.handleRequest(request, context),
                        JourneyErrorResponse.class);

        assertEquals(HttpStatus.SC_INTERNAL_SERVER_ERROR, response.getStatusCode());
        assertEquals(ErrorResponse.FAILED_TO_PARSE_CONFIG.getCode(), response.getCode());
        assertEquals(ErrorResponse.FAILED_TO_PARSE_CONFIG.getMessage(), response.getMessage());
        verify(clientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void shouldReturn500IfUnrecognisedCiReceived(boolean useContraIndicatorVC) throws Exception {
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(configService.enabled(USE_CONTRA_INDICATOR_VC)).thenReturn(useContraIndicatorVC);
        mockCiJourneyResponseException(
                useContraIndicatorVC, new UnrecognisedCiException("Unrecognised CI"));
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        JourneyErrorResponse response =
                toResponseClass(
                        ciScoringHandler.handleRequest(request, context),
                        JourneyErrorResponse.class);

        assertEquals(JOURNEY_ERROR, response.getJourney());
        assertEquals(HttpStatus.SC_INTERNAL_SERVER_ERROR, response.getStatusCode());
        assertEquals(ErrorResponse.UNRECOGNISED_CI_CODE.getCode(), response.getCode());
        assertEquals(ErrorResponse.UNRECOGNISED_CI_CODE.getMessage(), response.getMessage());
    }

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void shouldReturnJourneyNoMatchJourneyResponseForSeparateSessionBreachingCIs(
            boolean useContraIndicatorVC) throws Exception {
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        ipvSessionItem.setUserState(USER_STATE_INITIAL_CI_SCORING);
        when(configService.enabled(USE_CONTRA_INDICATOR_VC)).thenReturn(useContraIndicatorVC);
        mockCiJourneyResponse(
                useContraIndicatorVC, Optional.of(new JourneyResponse(JOURNEY_PYI_NO_MATCH)), true);
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        JourneyResponse response =
                toResponseClass(
                        ciScoringHandler.handleRequest(request, context), JourneyResponse.class);

        assertEquals(JOURNEY_PYI_NO_MATCH, response.getJourney());
    }

    private <T> T toResponseClass(Map<String, Object> handlerOutput, Class<T> responseClass) {
        return mapper.convertValue(handlerOutput, responseClass);
    }

    private void mockCiJourneyResponse(
            boolean useContraIndicatorVC,
            Optional<JourneyResponse> mockResponse,
            boolean separateSession)
            throws UnrecognisedCiException, ConfigException {
        if (useContraIndicatorVC) {
            when(gpg45ProfileEvaluator.getJourneyResponseForStoredContraIndicators(
                            any(), eq(separateSession), any()))
                    .thenReturn(mockResponse);
        } else {
            when(gpg45ProfileEvaluator.getJourneyResponseForStoredCis(any(), any()))
                    .thenReturn(mockResponse);
        }
    }

    private void mockCiJourneyResponseException(boolean useContraIndicatorVC, Exception exception)
            throws UnrecognisedCiException, ConfigException {
        if (useContraIndicatorVC) {
            when(gpg45ProfileEvaluator.getJourneyResponseForStoredContraIndicators(
                            any(), anyBoolean(), any()))
                    .thenThrow(exception);
        } else {
            when(gpg45ProfileEvaluator.getJourneyResponseForStoredCis(any(), any()))
                    .thenThrow(exception);
        }
    }
}
