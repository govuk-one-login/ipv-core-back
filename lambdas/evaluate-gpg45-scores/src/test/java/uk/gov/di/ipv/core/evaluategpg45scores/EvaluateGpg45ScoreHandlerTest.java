package uk.gov.di.ipv.core.evaluategpg45scores;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.google.gson.Gson;
import org.apache.http.HttpStatus;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.evaluategpg45scores.exception.UnknownEvidenceTypeException;
import uk.gov.di.ipv.core.evaluategpg45scores.gpg45.Gpg45Profile;
import uk.gov.di.ipv.core.evaluategpg45scores.gpg45.Gpg45ProfileEvaluator;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.JourneyResponse;
import uk.gov.di.ipv.core.library.service.UserIdentityService;

import java.text.ParseException;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.evaluategpg45scores.EvaluateGpg45ScoresHandler.JOURNEY_ERROR;
import static uk.gov.di.ipv.core.evaluategpg45scores.EvaluateGpg45ScoresHandler.JOURNEY_FAIL;
import static uk.gov.di.ipv.core.evaluategpg45scores.EvaluateGpg45ScoresHandler.JOURNEY_NEXT;
import static uk.gov.di.ipv.core.evaluategpg45scores.EvaluateGpg45ScoresHandler.JOURNEY_SESSION_END;
import static uk.gov.di.ipv.core.library.helpers.RequestHelper.IPV_SESSION_ID_HEADER;

@ExtendWith(MockitoExtension.class)
class EvaluateGpg45ScoreHandlerTest {

    private static final String TEST_SESSION_ID = "test-session-id";
    private static final APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
    public static final List<String> CREDENTIALS = List.of("Some", "gathered", "credentials");

    @Mock private Context context;
    @Mock private UserIdentityService userIdentityService;
    @Mock private Gpg45ProfileEvaluator gpg45ProfileEvaluator;
    @InjectMocks private EvaluateGpg45ScoresHandler evaluateGpg45ScoresHandler;

    private final Gson gson = new Gson();

    @BeforeAll
    static void setUp() {
        event.setHeaders(Map.of(IPV_SESSION_ID_HEADER, TEST_SESSION_ID));
    }

    @Test
    void shouldReturnJourneySessionEndIfScoresSatisfyM1AGpg45Profile() throws Exception {
        when(userIdentityService.getUserIssuedCredentials(TEST_SESSION_ID)).thenReturn(CREDENTIALS);
        when(gpg45ProfileEvaluator.credentialsSatisfyProfile(CREDENTIALS, Gpg45Profile.M1A))
                .thenReturn(true);

        var response = evaluateGpg45ScoresHandler.handleRequest(event, context);
        JourneyResponse journeyResponse = gson.fromJson(response.getBody(), JourneyResponse.class);

        assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        assertEquals(JOURNEY_SESSION_END, journeyResponse.getJourney());
        verify(userIdentityService).getUserIssuedCredentials(TEST_SESSION_ID);
    }

    @Test
    void shouldReturnJourneyFailIfAnyCredentialsAreNotEnoughForM1A() throws Exception {
        when(userIdentityService.getUserIssuedCredentials(TEST_SESSION_ID)).thenReturn(CREDENTIALS);
        when(gpg45ProfileEvaluator.anyCredentialsGatheredDoNotMeetM1A(CREDENTIALS))
                .thenReturn(true);

        var response = evaluateGpg45ScoresHandler.handleRequest(event, context);
        JourneyResponse journeyResponse = gson.fromJson(response.getBody(), JourneyResponse.class);

        assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        assertEquals(JOURNEY_FAIL, journeyResponse.getJourney());
        verify(userIdentityService).getUserIssuedCredentials(TEST_SESSION_ID);
    }

    @Test
    void shouldReturnJourneyNextIfScoresDoNotSatisfyM1AGpg45Profile() throws Exception {
        when(userIdentityService.getUserIssuedCredentials(TEST_SESSION_ID)).thenReturn(CREDENTIALS);
        when(gpg45ProfileEvaluator.credentialsSatisfyProfile(CREDENTIALS, Gpg45Profile.M1A))
                .thenReturn(false);

        var response = evaluateGpg45ScoresHandler.handleRequest(event, context);
        JourneyResponse journeyResponse = gson.fromJson(response.getBody(), JourneyResponse.class);

        assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        assertEquals(JOURNEY_NEXT, journeyResponse.getJourney());
        verify(userIdentityService).getUserIssuedCredentials(TEST_SESSION_ID);
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
    void shouldReturnJourneyErrorIfFailedToParseCredentials() throws Exception {
        when(userIdentityService.getUserIssuedCredentials(TEST_SESSION_ID)).thenReturn(CREDENTIALS);
        when(gpg45ProfileEvaluator.credentialsSatisfyProfile(CREDENTIALS, Gpg45Profile.M1A))
                .thenThrow(new ParseException("Whoops", 0));

        var response = evaluateGpg45ScoresHandler.handleRequest(event, context);
        JourneyResponse journeyResponse = gson.fromJson(response.getBody(), JourneyResponse.class);

        assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        assertEquals(JOURNEY_ERROR, journeyResponse.getJourney());
        verify(userIdentityService).getUserIssuedCredentials(TEST_SESSION_ID);
    }

    @Test
    void shouldReturnJourneyErrorIfCredentialOfUnknownType() throws Exception {
        when(userIdentityService.getUserIssuedCredentials(TEST_SESSION_ID)).thenReturn(CREDENTIALS);
        when(gpg45ProfileEvaluator.credentialsSatisfyProfile(CREDENTIALS, Gpg45Profile.M1A))
                .thenThrow(new UnknownEvidenceTypeException());

        var response = evaluateGpg45ScoresHandler.handleRequest(event, context);
        JourneyResponse journeyResponse = gson.fromJson(response.getBody(), JourneyResponse.class);

        assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        assertEquals(JOURNEY_ERROR, journeyResponse.getJourney());
        verify(userIdentityService).getUserIssuedCredentials(TEST_SESSION_ID);
    }
}
