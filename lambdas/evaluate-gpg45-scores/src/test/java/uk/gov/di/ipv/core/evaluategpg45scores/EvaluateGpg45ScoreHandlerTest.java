package uk.gov.di.ipv.core.evaluategpg45scores;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.gson.Gson;
import org.apache.http.HttpStatus;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.JourneyResponse;
import uk.gov.di.ipv.core.library.domain.gpg45.Gpg45Profile;
import uk.gov.di.ipv.core.library.domain.gpg45.Gpg45ProfileEvaluator;
import uk.gov.di.ipv.core.library.domain.gpg45.exception.UnknownEvidenceTypeException;
import uk.gov.di.ipv.core.library.dto.ClientSessionDetailsDto;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.CiStorageService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.service.UserIdentityService;

import java.text.ParseException;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.evaluategpg45scores.EvaluateGpg45ScoresHandler.JOURNEY_END;
import static uk.gov.di.ipv.core.evaluategpg45scores.EvaluateGpg45ScoresHandler.JOURNEY_NEXT;
import static uk.gov.di.ipv.core.library.helpers.RequestHelper.IPV_SESSION_ID_HEADER;

@ExtendWith(MockitoExtension.class)
class EvaluateGpg45ScoreHandlerTest {

    private static final String TEST_SESSION_ID = "test-session-id";
    private static final String TEST_USER_ID = "test-user-id";
    private static final String TEST_JOURNEY_ID = "test-journey-id";
    private static final APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
    public static final List<String> CREDENTIALS = List.of("Some", "gathered", "credentials");
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Mock private Context context;
    @Mock private UserIdentityService userIdentityService;
    @Mock private IpvSessionService ipvSessionService;
    @Mock private Gpg45ProfileEvaluator gpg45ProfileEvaluator;
    @Mock private CiStorageService ciStorageService;
    @InjectMocks private EvaluateGpg45ScoresHandler evaluateGpg45ScoresHandler;

    private final Gson gson = new Gson();

    private IpvSessionItem ipvSessionItem;

    @BeforeAll
    static void setUp() {
        event.setHeaders(Map.of(IPV_SESSION_ID_HEADER, TEST_SESSION_ID));
    }

    @BeforeEach
    void setUpEach() {
        ipvSessionItem = new IpvSessionItem();
        ClientSessionDetailsDto clientSessionDetailsDto = new ClientSessionDetailsDto();
        clientSessionDetailsDto.setUserId(TEST_USER_ID);
        clientSessionDetailsDto.setGovukSigninJourneyId(TEST_JOURNEY_ID);
        ipvSessionItem.setClientSessionDetails(clientSessionDetailsDto);
    }

    @Test
    void shouldReturnJourneySessionEndIfScoresSatisfyM1AGpg45Profile() throws Exception {
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(userIdentityService.getUserIssuedCredentials(TEST_USER_ID)).thenReturn(CREDENTIALS);
        when(gpg45ProfileEvaluator.contraIndicatorsPresent(CREDENTIALS))
                .thenReturn(Optional.empty());
        when(gpg45ProfileEvaluator.credentialsSatisfyProfile(CREDENTIALS, Gpg45Profile.M1B))
                .thenReturn(false);
        when(gpg45ProfileEvaluator.credentialsSatisfyProfile(CREDENTIALS, Gpg45Profile.M1A))
                .thenReturn(true);

        var response = evaluateGpg45ScoresHandler.handleRequest(event, context);
        JourneyResponse journeyResponse = gson.fromJson(response.getBody(), JourneyResponse.class);

        assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        assertEquals(JOURNEY_END, journeyResponse.getJourney());
        verify(userIdentityService).getUserIssuedCredentials(TEST_USER_ID);
    }

    @Test
    void shouldReturnJourneySessionEndIfScoresSatisfyM1BGpg45Profile() throws Exception {
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(userIdentityService.getUserIssuedCredentials(TEST_USER_ID)).thenReturn(CREDENTIALS);
        when(gpg45ProfileEvaluator.contraIndicatorsPresent(CREDENTIALS))
                .thenReturn(Optional.empty());
        when(gpg45ProfileEvaluator.credentialsSatisfyProfile(CREDENTIALS, Gpg45Profile.M1B))
                .thenReturn(true);

        var response = evaluateGpg45ScoresHandler.handleRequest(event, context);
        JourneyResponse journeyResponse = gson.fromJson(response.getBody(), JourneyResponse.class);

        assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        assertEquals(JOURNEY_END, journeyResponse.getJourney());
        verify(userIdentityService).getUserIssuedCredentials(TEST_USER_ID);
    }

    @Test
    void shouldReturnJourneyNextIfScoresDoNotSatisfyM1AGpg45Profile() throws Exception {
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(userIdentityService.getUserIssuedCredentials(TEST_USER_ID)).thenReturn(CREDENTIALS);
        when(gpg45ProfileEvaluator.contraIndicatorsPresent(CREDENTIALS))
                .thenReturn(Optional.empty());
        when(gpg45ProfileEvaluator.credentialsSatisfyProfile(CREDENTIALS, Gpg45Profile.M1B))
                .thenReturn(false);
        when(gpg45ProfileEvaluator.credentialsSatisfyProfile(CREDENTIALS, Gpg45Profile.M1A))
                .thenReturn(false);

        var response = evaluateGpg45ScoresHandler.handleRequest(event, context);
        JourneyResponse journeyResponse = gson.fromJson(response.getBody(), JourneyResponse.class);

        assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        assertEquals(JOURNEY_NEXT, journeyResponse.getJourney());
        verify(userIdentityService).getUserIssuedCredentials(TEST_USER_ID);
    }

    @Test
    void shouldReturn400IfSessionIdNotInHeader() {
        APIGatewayProxyRequestEvent eventWithoutHeaders = new APIGatewayProxyRequestEvent();

        var response = evaluateGpg45ScoresHandler.handleRequest(eventWithoutHeaders, context);
        var error = gson.fromJson(response.getBody(), Map.class);

        assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        assertEquals(
                ErrorResponse.MISSING_IPV_SESSION_ID.getMessage(), error.get("error_description"));
    }

    @Test
    void shouldReturn500IfFailedToParseCredentials() throws Exception {
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(userIdentityService.getUserIssuedCredentials(TEST_USER_ID)).thenReturn(CREDENTIALS);
        when(gpg45ProfileEvaluator.contraIndicatorsPresent(CREDENTIALS))
                .thenReturn(Optional.empty());
        when(gpg45ProfileEvaluator.credentialsSatisfyProfile(CREDENTIALS, Gpg45Profile.M1B))
                .thenReturn(false);
        when(gpg45ProfileEvaluator.credentialsSatisfyProfile(CREDENTIALS, Gpg45Profile.M1A))
                .thenThrow(new ParseException("Whoops", 0));

        var response = evaluateGpg45ScoresHandler.handleRequest(event, context);
        Map<String, Object> responseMap =
                objectMapper.readValue(response.getBody(), new TypeReference<>() {});

        assertEquals(HttpStatus.SC_INTERNAL_SERVER_ERROR, response.getStatusCode());
        assertEquals(
                ErrorResponse.FAILED_TO_PARSE_ISSUED_CREDENTIALS.getCode(),
                responseMap.get("code"));
        assertEquals(
                ErrorResponse.FAILED_TO_PARSE_ISSUED_CREDENTIALS.getMessage(),
                responseMap.get("message"));
        verify(userIdentityService).getUserIssuedCredentials(TEST_USER_ID);
    }

    @Test
    void shouldReturn500IfCredentialOfUnknownType() throws Exception {
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(userIdentityService.getUserIssuedCredentials(TEST_USER_ID)).thenReturn(CREDENTIALS);
        when(gpg45ProfileEvaluator.contraIndicatorsPresent(CREDENTIALS))
                .thenReturn(Optional.empty());
        when(gpg45ProfileEvaluator.credentialsSatisfyProfile(CREDENTIALS, Gpg45Profile.M1B))
                .thenReturn(false);
        when(gpg45ProfileEvaluator.credentialsSatisfyProfile(CREDENTIALS, Gpg45Profile.M1A))
                .thenThrow(new UnknownEvidenceTypeException());

        var response = evaluateGpg45ScoresHandler.handleRequest(event, context);
        Map<String, Object> responseMap =
                objectMapper.readValue(response.getBody(), new TypeReference<>() {});

        assertEquals(HttpStatus.SC_INTERNAL_SERVER_ERROR, response.getStatusCode());
        assertEquals(
                ErrorResponse.FAILED_TO_DETERMINE_CREDENTIAL_TYPE.getCode(),
                responseMap.get("code"));
        assertEquals(
                ErrorResponse.FAILED_TO_DETERMINE_CREDENTIAL_TYPE.getMessage(),
                responseMap.get("message"));
        verify(userIdentityService).getUserIssuedCredentials(TEST_USER_ID);
    }

    @Test
    void shouldCallCIStorageSystemToGetCIs() throws Exception {
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(userIdentityService.getUserIssuedCredentials(TEST_USER_ID)).thenReturn(CREDENTIALS);
        when(gpg45ProfileEvaluator.credentialsSatisfyProfile(CREDENTIALS, Gpg45Profile.M1B))
                .thenReturn(false);
        when(gpg45ProfileEvaluator.credentialsSatisfyProfile(CREDENTIALS, Gpg45Profile.M1A))
                .thenReturn(true);

        evaluateGpg45ScoresHandler.handleRequest(event, context);

        verify(ciStorageService).getCIs(TEST_USER_ID, TEST_JOURNEY_ID);
    }

    @Test
    void shouldNotThrowIfGetCIsThrows() throws Exception {
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(userIdentityService.getUserIssuedCredentials(TEST_USER_ID)).thenReturn(CREDENTIALS);
        when(gpg45ProfileEvaluator.credentialsSatisfyProfile(CREDENTIALS, Gpg45Profile.M1B))
                .thenReturn(false);
        when(gpg45ProfileEvaluator.credentialsSatisfyProfile(CREDENTIALS, Gpg45Profile.M1A))
                .thenReturn(true);
        doThrow(new RuntimeException("Ruh'oh")).when(ciStorageService).getCIs(any(), any());

        assertDoesNotThrow(() -> evaluateGpg45ScoresHandler.handleRequest(event, context));

        verify(ciStorageService).getCIs(TEST_USER_ID, TEST_JOURNEY_ID);
    }

    @Test
    void shouldReturnJourneyErrorJourneyResponseIfCiAreFoundOnVcs() throws Exception {
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(userIdentityService.getUserIssuedCredentials(TEST_USER_ID)).thenReturn(CREDENTIALS);
        when(gpg45ProfileEvaluator.contraIndicatorsPresent(CREDENTIALS))
                .thenReturn(Optional.of(new JourneyResponse("/journey/pyi-no-match")));

        var response = evaluateGpg45ScoresHandler.handleRequest(event, context);
        JourneyResponse journeyResponse = gson.fromJson(response.getBody(), JourneyResponse.class);

        assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        assertEquals("/journey/pyi-no-match", journeyResponse.getJourney());
    }
}
