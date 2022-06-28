package uk.gov.di.ipv.core.validatecricheck;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.google.gson.Gson;
import org.apache.http.HttpStatus;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.JourneyResponse;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.core.library.service.UserIdentityService;
import uk.gov.di.ipv.core.validatecricheck.validation.CriCheckValidator;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.validatecricheck.ValidateCriCheckHandler.CRI_ID;
import static uk.gov.di.ipv.core.validatecricheck.ValidateCriCheckHandler.IPV_SESSION_ID_HEADER_KEY;
import static uk.gov.di.ipv.core.validatecricheck.ValidateCriCheckHandler.JOURNEY_FAIL;
import static uk.gov.di.ipv.core.validatecricheck.ValidateCriCheckHandler.JOURNEY_NEXT;

@ExtendWith(MockitoExtension.class)
class ValidateCriCheckHandlerTest {

    private final Gson gson = new Gson();
    private final String criId = "testCriId";
    private final String sessionId = "testSessionId";

    @Mock private Context context;
    @Mock private CriCheckValidator mockCriCheckValidator;
    @Mock private UserIdentityService userIdentityService;
    @InjectMocks private ValidateCriCheckHandler validateCriCheckHandler;

    @Test
    void shouldReturnJourneyNextForSuccessfulCheck() throws HttpResponseExceptionWithErrorBody {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setPathParameters(Map.of(CRI_ID, criId));
        event.setHeaders(Map.of(IPV_SESSION_ID_HEADER_KEY, sessionId));

        when(mockCriCheckValidator.isSuccess(any())).thenReturn(true);

        var response = validateCriCheckHandler.handleRequest(event, context);
        JourneyResponse journeyResponse = gson.fromJson(response.getBody(), JourneyResponse.class);

        assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        assertEquals(JOURNEY_NEXT, journeyResponse.getJourney());
        verify(userIdentityService).getUserIssuedCredential(sessionId, criId);
    }

    @Test
    void shouldReturnJourneyFailForUnsuccessfulCheck() throws HttpResponseExceptionWithErrorBody {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setPathParameters(Map.of(CRI_ID, criId));
        event.setHeaders(Map.of(IPV_SESSION_ID_HEADER_KEY, sessionId));

        when(mockCriCheckValidator.isSuccess(any())).thenReturn(false);

        var response = validateCriCheckHandler.handleRequest(event, context);
        JourneyResponse journeyResponse = gson.fromJson(response.getBody(), JourneyResponse.class);

        assertEquals(HttpStatus.SC_OK, response.getStatusCode());
        assertEquals(JOURNEY_FAIL, journeyResponse.getJourney());
        verify(userIdentityService).getUserIssuedCredential(sessionId, criId);
    }

    @Test
    void shouldReturn400IfCriIdPathParameterIsNull() {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setHeaders(Map.of(IPV_SESSION_ID_HEADER_KEY, sessionId));

        var response = validateCriCheckHandler.handleRequest(event, context);
        var error = gson.fromJson(response.getBody(), Map.class);

        assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        assertEquals(ErrorResponse.MISSING_CREDENTIAL_ISSUER_ID.getMessage(), error.get("message"));
    }

    @Test
    void shouldReturn400IfCriIdPathParameterIsEmpty() {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setPathParameters(Map.of(CRI_ID, ""));
        event.setHeaders(Map.of(IPV_SESSION_ID_HEADER_KEY, sessionId));

        var response = validateCriCheckHandler.handleRequest(event, context);
        var error = gson.fromJson(response.getBody(), Map.class);

        assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        assertEquals(ErrorResponse.MISSING_CREDENTIAL_ISSUER_ID.getMessage(), error.get("message"));
    }

    @Test
    void shouldReturn400IfIpvSessionIdHeaderIsNull() {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setPathParameters(Map.of(CRI_ID, criId));

        var response = validateCriCheckHandler.handleRequest(event, context);
        var error = gson.fromJson(response.getBody(), Map.class);

        assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        assertEquals(ErrorResponse.MISSING_IPV_SESSION_ID.getMessage(), error.get("message"));
    }

    @Test
    void shouldReturnJourneyErrorIfIpvSessionIdHeaderIsMissing() {
        APIGatewayProxyRequestEvent event = new APIGatewayProxyRequestEvent();
        event.setPathParameters(Map.of(CRI_ID, criId));
        event.setHeaders(Map.of(IPV_SESSION_ID_HEADER_KEY, ""));

        var response = validateCriCheckHandler.handleRequest(event, context);
        var error = gson.fromJson(response.getBody(), Map.class);

        assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
        assertEquals(ErrorResponse.MISSING_IPV_SESSION_ID.getMessage(), error.get("message"));
    }
}
