package uk.gov.di.ipv.core.checkgpg45score;

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
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.JourneyErrorResponse;
import uk.gov.di.ipv.core.library.domain.JourneyResponse;
import uk.gov.di.ipv.core.library.domain.ProcessRequest;
import uk.gov.di.ipv.core.library.gpg45.Gpg45ProfileEvaluator;
import uk.gov.di.ipv.core.library.gpg45.Gpg45Scores;
import uk.gov.di.ipv.core.library.gpg45.exception.UnknownEvidenceTypeException;
import uk.gov.di.ipv.core.library.helpers.SecureTokenHelper;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.ClientOAuthSessionDetailsService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.service.UserIdentityService;
import uk.gov.di.ipv.core.library.verifiablecredential.service.SessionCredentialsService;
import uk.gov.di.ipv.core.library.verifiablecredential.service.VerifiableCredentialService;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.config.CoreFeatureFlag.SESSION_CREDENTIALS_TABLE_READS;

@ExtendWith(MockitoExtension.class)
class CheckGpg45ScoreHandlerTest {
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final String TEST_SESSION_ID = "test-session-id";
    private static final String TEST_CLIENT_SOURCE_IP = "test-client-source-ip";
    private static final String TEST_USER_ID = "test-user-id";
    private static final String TEST_JOURNEY_ID = "test-journey-id";
    private static final JourneyResponse JOURNEY_MET = new JourneyResponse("/journey/met");
    private static final JourneyResponse JOURNEY_UNMET = new JourneyResponse("/journey/unmet");
    private static final String TEST_CLIENT_OAUTH_SESSION_ID =
            SecureTokenHelper.getInstance().generate();
    private static ProcessRequest request;
    @Mock private ClientOAuthSessionDetailsService clientOAuthSessionDetailsService;
    @Mock private ConfigService configService;
    @Mock private Context context;
    @Mock private Gpg45ProfileEvaluator gpg45ProfileEvaluator;
    @Mock private IpvSessionService ipvSessionService;
    @Mock private UserIdentityService userIdentityService;
    @Mock private VerifiableCredentialService mockVerifiableCredentialService;
    @Mock private SessionCredentialsService mockSessionCredentialsService;
    @InjectMocks private CheckGpg45ScoreHandler checkGpg45ScoreHandler;
    private IpvSessionItem ipvSessionItem;
    private ClientOAuthSessionItem clientOAuthSessionItem;

    @BeforeAll
    static void setUp() {
        request =
                ProcessRequest.processRequestBuilder()
                        .journey(TEST_JOURNEY_ID)
                        .ipAddress(TEST_CLIENT_SOURCE_IP)
                        .ipvSessionId(TEST_SESSION_ID)
                        .clientOAuthSessionId(TEST_CLIENT_OAUTH_SESSION_ID)
                        .lambdaInput(new HashMap<>(Map.of("scoreThreshold", 2)))
                        .build();
    }

    @BeforeEach
    void setUpEach() {
        ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setClientOAuthSessionId(TEST_CLIENT_OAUTH_SESSION_ID);
        ipvSessionItem.setIpvSessionId(TEST_SESSION_ID);

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
    @ValueSource(booleans = {true, false})
    void handlerShouldReturnJourneyMetPathIfThresholdMetFraud(boolean sessionCredentialsTableReads)
            throws Exception {
        request.getLambdaInput().put("scoreType", "fraud");
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(gpg45ProfileEvaluator.buildScore(any()))
                .thenReturn(new Gpg45Scores(Gpg45Scores.EV_00, 0, 2, 0));
        when(configService.enabled(SESSION_CREDENTIALS_TABLE_READS))
                .thenReturn(sessionCredentialsTableReads);

        Map<String, Object> journeyResponse =
                checkGpg45ScoreHandler.handleRequest(request, context);
        assertEquals(JOURNEY_MET.toObjectMap(), journeyResponse);
        if (sessionCredentialsTableReads) {
            verify(mockSessionCredentialsService).getCredentials(TEST_SESSION_ID, TEST_USER_ID);
        } else {
            verify(mockVerifiableCredentialService).getVcs(TEST_USER_ID);
        }
    }

    @Test
    void handlerShouldReturnJourneyMetPathIfThresholdMetActivity() throws Exception {
        request.getLambdaInput().put("scoreType", "activity");
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(gpg45ProfileEvaluator.buildScore(any()))
                .thenReturn(new Gpg45Scores(Gpg45Scores.EV_00, 2, 0, 0));

        Map<String, Object> journeyResponse =
                checkGpg45ScoreHandler.handleRequest(request, context);
        assertEquals(JOURNEY_MET.toObjectMap(), journeyResponse);
        verify(mockVerifiableCredentialService, times(1)).getVcs(TEST_USER_ID);
    }

    @Test
    void handlerShouldReturnJourneyMetPathIfThresholdMetVerification() throws Exception {
        request.getLambdaInput().put("scoreType", "verification");
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(gpg45ProfileEvaluator.buildScore(any()))
                .thenReturn(new Gpg45Scores(Gpg45Scores.EV_00, 0, 0, 2));

        Map<String, Object> journeyResponse =
                checkGpg45ScoreHandler.handleRequest(request, context);
        assertEquals(JOURNEY_MET.toObjectMap(), journeyResponse);
        verify(mockVerifiableCredentialService, times(1)).getVcs(TEST_USER_ID);
    }

    @Test
    void handlerShouldReturnJourneyUnmetPathIfThresholdNotMet() throws Exception {
        request.getLambdaInput().put("scoreType", "fraud");
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(gpg45ProfileEvaluator.buildScore(any()))
                .thenReturn(new Gpg45Scores(Gpg45Scores.EV_00, 0, 1, 0));

        JourneyResponse response =
                toResponseClass(
                        checkGpg45ScoreHandler.handleRequest(request, context),
                        JourneyResponse.class);
        assertEquals(JOURNEY_UNMET.getJourney(), response.getJourney());
        verify(mockVerifiableCredentialService, times(1)).getVcs(TEST_USER_ID);
    }

    @Test
    void shouldReturn400IfSessionIdNotInRequest() {
        ProcessRequest requestWithoutSessionId =
                ProcessRequest.processRequestBuilder().ipAddress(TEST_CLIENT_SOURCE_IP).build();

        JourneyErrorResponse response =
                toResponseClass(
                        checkGpg45ScoreHandler.handleRequest(requestWithoutSessionId, context),
                        JourneyErrorResponse.class);

        assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        assertEquals(ErrorResponse.MISSING_IPV_SESSION_ID.getCode(), response.getCode());
        verify(clientOAuthSessionDetailsService, times(0)).getClientOAuthSession(any());
    }

    @Test
    void shouldReturn500IfCredentialOfUnknownType() throws Exception {
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(gpg45ProfileEvaluator.buildScore(any())).thenThrow(new UnknownEvidenceTypeException());
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        JourneyErrorResponse response =
                toResponseClass(
                        checkGpg45ScoreHandler.handleRequest(request, context),
                        JourneyErrorResponse.class);
        assertEquals(HttpStatus.SC_INTERNAL_SERVER_ERROR, response.getStatusCode());
        assertEquals(
                ErrorResponse.FAILED_TO_DETERMINE_CREDENTIAL_TYPE.getCode(), response.getCode());
        assertEquals(
                ErrorResponse.FAILED_TO_DETERMINE_CREDENTIAL_TYPE.getMessage(),
                response.getMessage());
        verify(clientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());
        verify(mockVerifiableCredentialService, times(1)).getVcs(TEST_USER_ID);
    }

    @Test
    void shouldReturn500IfUnknownScoreType() throws Exception {
        request.getLambdaInput().put("scoreType", "unknown");
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(gpg45ProfileEvaluator.buildScore(any()))
                .thenReturn(new Gpg45Scores(Gpg45Scores.EV_00, 0, 2, 0));

        JourneyErrorResponse response =
                toResponseClass(
                        checkGpg45ScoreHandler.handleRequest(request, context),
                        JourneyErrorResponse.class);
        assertEquals(HttpStatus.SC_INTERNAL_SERVER_ERROR, response.getStatusCode());
        assertEquals(ErrorResponse.UNKNOWN_SCORE_TYPE.getCode(), response.getCode());
        assertEquals(ErrorResponse.UNKNOWN_SCORE_TYPE.getMessage(), response.getMessage());
        verify(mockVerifiableCredentialService, times(1)).getVcs(TEST_USER_ID);
        verify(clientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());
    }

    private <T> T toResponseClass(Map<String, Object> handlerOutput, Class<T> responseClass) {
        return OBJECT_MAPPER.convertValue(handlerOutput, responseClass);
    }
}
