package uk.gov.di.ipv.core.storetriagedata;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.exceptions.IpvSessionNotFoundException;
import uk.gov.di.ipv.core.library.persistence.item.DynamicRoutingState;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.storetriagedata.triage.TriageQuestions;

import java.util.Map;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.helpers.RequestHelper.IPV_SESSION_ID_HEADER;

@ExtendWith(MockitoExtension.class)
class StoreTriageDataHandlerTest {
    private static final String TEST_SESSION_ID = "test-session-id";

    @Mock private Context context;
    @Mock private ConfigService configService;
    @Mock private IpvSessionService ipvSessionService;

    private StoreTriageDataHandler handler;
    private IpvSessionItem ipvSessionItem;

    @BeforeEach
    void setUp() {
        handler =
                new StoreTriageDataHandler(
                        configService, ipvSessionService, TriageQuestions.createDefault());
        ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setIpvSessionId(TEST_SESSION_ID);
        ipvSessionItem.setDynamicRoutingState(new DynamicRoutingState());
    }

    @Test
    void shouldStoreLivesInUkTrueWhenUkAnswered() throws Exception {
        // Arrange
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        var event = request("{\"pageId\":\"live-in-uk\",\"answers\":[\"uk\"]}");

        // Act
        var response = handler.handleRequest(event, context);

        // Assert
        assertEquals(200, response.getStatusCode());
        assertTrue(ipvSessionItem.getDynamicRoutingState().getLivesInUk());
        verify(ipvSessionService).updateIpvSession(ipvSessionItem);
    }

    @Test
    void shouldStoreLivesInUkFalseWhenInternationalAnswered() throws Exception {
        // Arrange
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        var event = request("{\"pageId\":\"live-in-uk\",\"answers\":[\"international\"]}");

        // Act
        var response = handler.handleRequest(event, context);

        // Assert
        assertEquals(200, response.getStatusCode());
        assertFalse(ipvSessionItem.getDynamicRoutingState().getLivesInUk());
        verify(ipvSessionService).updateIpvSession(ipvSessionItem);
    }

    @Test
    void shouldCreateDynamicRoutingStateIfSessionHasNone() throws Exception {
        // Arrange
        ipvSessionItem.setDynamicRoutingState(null);
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        var event = request("{\"pageId\":\"live-in-uk\",\"answers\":[\"uk\"]}");

        // Act
        var response = handler.handleRequest(event, context);

        // Assert
        assertEquals(200, response.getStatusCode());
        assertTrue(ipvSessionItem.getDynamicRoutingState().getLivesInUk());
    }

    @Test
    void shouldReturn400AndNotUpdateSessionForUnknownPage() throws Exception {
        // Arrange
        var event = request("{\"pageId\":\"not-a-page\",\"answers\":[\"uk\"]}");

        // Act
        var response = handler.handleRequest(event, context);

        // Assert
        assertEquals(400, response.getStatusCode());
        assertThat(response.getBody(), containsString(codeOf(ErrorResponse.UNKNOWN_TRIAGE_PAGE)));
        verify(ipvSessionService, never()).updateIpvSession(any());
    }

    @Test
    void shouldReturn400AndNotUpdateSessionForInvalidAnswer() throws Exception {
        // Arrange
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        var event = request("{\"pageId\":\"live-in-uk\",\"answers\":[\"mars\"]}");

        // Act
        var response = handler.handleRequest(event, context);

        // Assert
        assertEquals(400, response.getStatusCode());
        assertThat(response.getBody(), containsString(codeOf(ErrorResponse.INVALID_TRIAGE_ANSWER)));
        assertNull(ipvSessionItem.getDynamicRoutingState().getLivesInUk());
        verify(ipvSessionService, never()).updateIpvSession(any());
    }

    @Test
    void shouldReturn400ForMultipleAnswersToSingleChoiceQuestion() throws Exception {
        // Arrange
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        var event = request("{\"pageId\":\"live-in-uk\",\"answers\":[\"uk\",\"international\"]}");

        // Act
        var response = handler.handleRequest(event, context);

        // Assert
        assertEquals(400, response.getStatusCode());
        assertNull(ipvSessionItem.getDynamicRoutingState().getLivesInUk());
        verify(ipvSessionService, never()).updateIpvSession(any());
    }

    @Test
    void shouldReturn400ForMissingAnswers() throws Exception {
        // Arrange
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        var event = request("{\"pageId\":\"live-in-uk\"}");

        // Act
        var response = handler.handleRequest(event, context);

        // Assert
        assertEquals(400, response.getStatusCode());
        verify(ipvSessionService, never()).updateIpvSession(any());
    }

    @Test
    void shouldReturn400ForUnparseableBody() {
        // Arrange
        var event = request("not json");

        // Act
        var response = handler.handleRequest(event, context);

        // Assert
        assertEquals(400, response.getStatusCode());
        assertThat(
                response.getBody(),
                containsString(codeOf(ErrorResponse.INVALID_STORE_TRIAGE_DATA_REQUEST)));
    }

    @Test
    void shouldReturn400ForMissingBody() {
        // Arrange
        var event = request(null);

        // Act
        var response = handler.handleRequest(event, context);

        // Assert
        assertEquals(400, response.getStatusCode());
        assertThat(
                response.getBody(),
                containsString(codeOf(ErrorResponse.INVALID_STORE_TRIAGE_DATA_REQUEST)));
    }

    @Test
    void shouldReturn400ForMissingPageId() {
        // Arrange
        var event = request("{\"answers\":[\"uk\"]}");

        // Act
        var response = handler.handleRequest(event, context);

        // Assert
        assertEquals(400, response.getStatusCode());
        assertThat(
                response.getBody(),
                containsString(codeOf(ErrorResponse.INVALID_STORE_TRIAGE_DATA_REQUEST)));
    }

    @Test
    void shouldReturn400WhenSessionIdHeaderMissing() throws Exception {
        // Arrange
        var event = new APIGatewayProxyRequestEvent();
        event.setBody("{\"pageId\":\"live-in-uk\",\"answers\":[\"uk\"]}");
        event.setHeaders(Map.of());

        // Act
        var response = handler.handleRequest(event, context);

        // Assert
        assertEquals(400, response.getStatusCode());
        assertThat(
                response.getBody(), containsString(codeOf(ErrorResponse.MISSING_IPV_SESSION_ID)));
        verify(ipvSessionService, never()).updateIpvSession(any());
    }

    @Test
    void shouldReturn400WhenSessionNotFound() throws Exception {
        // Arrange
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID))
                .thenThrow(new IpvSessionNotFoundException("not found"));
        var event = request("{\"pageId\":\"live-in-uk\",\"answers\":[\"uk\"]}");

        // Act
        var response = handler.handleRequest(event, context);

        // Assert
        assertEquals(400, response.getStatusCode());
        assertThat(response.getBody(), containsString(codeOf(ErrorResponse.IPV_SESSION_NOT_FOUND)));
        verify(ipvSessionService, never()).updateIpvSession(any());
    }

    private static String codeOf(ErrorResponse errorResponse) {
        return String.valueOf(errorResponse.getCode());
    }

    private static APIGatewayProxyRequestEvent request(String body) {
        var event = new APIGatewayProxyRequestEvent();
        event.setBody(body);
        event.setHeaders(Map.of(IPV_SESSION_ID_HEADER, TEST_SESSION_ID));
        return event;
    }
}
