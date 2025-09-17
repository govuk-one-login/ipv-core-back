package uk.gov.di.ipv.core.fetchjourneytransitions;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.logs.AWSLogs;
import com.amazonaws.services.logs.model.*;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.http.HttpStatus;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.fetchjourneytransitions.domain.TransitionCount;

import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class FetchJourneyTransitionHandlerTest {

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    private static final String TEST_QUERY_ID = "test-query-id";
    private static final List<ResultField> TEST_QUERY_RESULT =
            List.of(
                    new ResultField().withField("fromJourney").withValue("NEW_P2_IDENTITY"),
                    new ResultField().withField("from").withValue("IPV_SUCCESS_PAGE"),
                    new ResultField().withField("toJourney").withValue("NEW_P2_IDENTITY"),
                    new ResultField().withField("to").withValue("RETURN_TO_RP"),
                    new ResultField().withField("transitions").withValue("231"));

    public static final String TEST_GOVUK_JOURNEY_ID = "40a89427-71f2-4ad5-ac65-41a6b641d308";
    private static final String TEST_IPV_SESSION_ID = "u7zeydbeSw6vnxBttMRPj-cmlEb4HGc4YxTQR8ORiOo";
    private static final List<ResultField> TEST_QUERY_RESULT_SINGLE_JOURNEY =
            List.of(
                    new ResultField().withField("fromJourney").withValue("NEW_P2_IDENTITY"),
                    new ResultField().withField("from").withValue("IPV_SUCCESS_PAGE"),
                    new ResultField().withField("toJourney").withValue("NEW_P2_IDENTITY"),
                    new ResultField().withField("to").withValue("RETURN_TO_RP"),
                    new ResultField().withField("transitions").withValue("1"));

    @Mock private AWSLogs mockLogsClient;
    @Mock private Context mockContext;
    private FetchJourneyTransitionsHandler handler;

    @BeforeEach
    void setup() {
        handler = new FetchJourneyTransitionsHandler(mockLogsClient);
    }

    @Test
    void handlerShouldReturnJourneyTransitions() throws Exception {
        // Arrange
        APIGatewayProxyRequestEvent request =
                new APIGatewayProxyRequestEvent()
                        .withQueryStringParameters(
                                Map.of(
                                        "fromDate", "2025-09-15T12:45+01:00",
                                        "toDate", "2025-09-15T13:15+01:00"));

        when(mockLogsClient.startQuery(any()))
                .thenReturn(new StartQueryResult().withQueryId(TEST_QUERY_ID));
        when(mockLogsClient.getQueryResults(
                        new GetQueryResultsRequest().withQueryId(TEST_QUERY_ID)))
                .thenReturn(new GetQueryResultsResult().withStatus("Running"))
                .thenReturn(
                        new GetQueryResultsResult()
                                .withStatus("Complete")
                                .withResults(List.of(TEST_QUERY_RESULT)));

        // Act
        var response = handler.handleRequest(request, mockContext);
        var body = response.getBody();
        List<TransitionCount> transitionCounts =
                OBJECT_MAPPER.readValue(body, new TypeReference<>() {});

        // Assert
        assertEquals(200, response.getStatusCode());
        assertEquals(1, transitionCounts.size());
        TransitionCount transitionCount = transitionCounts.get(0);
        assertEquals("NEW_P2_IDENTITY", transitionCount.fromJourney());
        assertEquals("IPV_SUCCESS_PAGE", transitionCount.from());
        assertEquals("NEW_P2_IDENTITY", transitionCount.toJourney());
        assertEquals("RETURN_TO_RP", transitionCount.to());
        assertEquals(231, transitionCount.count());
    }

    @ParameterizedTest
    @MethodSource("getValidRequestData")
    void handlerShouldReturnJourneyTransitionsWhenJourneyIdIsProvided(Map<String, String> inputData)
            throws JsonProcessingException {
        // Arrange
        var request = new APIGatewayProxyRequestEvent().withQueryStringParameters(inputData);

        when(mockLogsClient.startQuery(any()))
                .thenReturn(new StartQueryResult().withQueryId(TEST_QUERY_ID));
        when(mockLogsClient.getQueryResults(
                        new GetQueryResultsRequest().withQueryId(TEST_QUERY_ID)))
                .thenReturn(new GetQueryResultsResult().withStatus("Running"))
                .thenReturn(
                        new GetQueryResultsResult()
                                .withStatus("Complete")
                                .withResults(List.of(TEST_QUERY_RESULT_SINGLE_JOURNEY)));

        // Act
        var response = handler.handleRequest(request, mockContext);
        var body = response.getBody();
        List<TransitionCount> transitionCounts =
                OBJECT_MAPPER.readValue(body, new TypeReference<>() {});

        // Assert
        assertEquals(200, response.getStatusCode());
        assertEquals(1, transitionCounts.size());
        TransitionCount transitionCount = transitionCounts.get(0);
        assertEquals("NEW_P2_IDENTITY", transitionCount.fromJourney());
        assertEquals("IPV_SUCCESS_PAGE", transitionCount.from());
        assertEquals("NEW_P2_IDENTITY", transitionCount.toJourney());
        assertEquals("RETURN_TO_RP", transitionCount.to());
        assertEquals(1, transitionCount.count());
    }

    private static Stream<Arguments> getValidRequestData() {
        return Stream.of(
                Arguments.of(
                        Map.of(
                                "fromDate", "2025-09-15T12:45+01:00",
                                "toDate", "2025-09-15T13:15+01:00",
                                "govukJourneyId", TEST_GOVUK_JOURNEY_ID)),
                Arguments.of(
                        Map.of(
                                "fromDate", "2025-09-15T12:45+01:00",
                                "toDate", "2025-09-15T13:15+01:00",
                                "ipvSessionId", TEST_IPV_SESSION_ID)));
    }

    @ParameterizedTest
    @MethodSource("getInvalidIdRequests")
    void shouldThrowIfIdIsInInvalidFormat(Map<String, String> inputData) {
        // Arrange
        var request = new APIGatewayProxyRequestEvent().withQueryStringParameters(inputData);

        // Act
        var response = handler.handleRequest(request, mockContext);

        // Assert
        assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
    }

    private static Stream<Arguments> getInvalidIdRequests() {
        return Stream.of(
                Arguments.of(
                        Map.of(
                                "fromDate", "2025-09-15T12:45+01:00",
                                "toDate", "2025-09-15T13:15+01:00",
                                "ipvSessionId", "invalid^format")),
                Arguments.of(
                        Map.of(
                                "fromDate", "2025-09-15T12:45+01:00",
                                "toDate", "2025-09-15T13:15+01:00",
                                "govukJourneyId", "not-uuid-v4")));
    }

    @Test
    void shouldReturn400IfJourneyIdAndSessionIdIsPresented() {
        // Arrange
        var request =
                new APIGatewayProxyRequestEvent()
                        .withQueryStringParameters(
                                Map.of(
                                        "fromDate",
                                        "2025-09-15T12:45+01:00",
                                        "toDate",
                                        "2025-09-15T13:15+01:00",
                                        "ipvSessionId",
                                        TEST_IPV_SESSION_ID,
                                        "govukJourneyId",
                                        TEST_GOVUK_JOURNEY_ID));

        // Act
        var response = handler.handleRequest(request, mockContext);

        // Assert
        assertEquals(HttpStatus.SC_BAD_REQUEST, response.getStatusCode());
    }

    @Test
    void handlerShouldThrowWhenFailedQueryResult() {
        // Arrange
        APIGatewayProxyRequestEvent request =
                new APIGatewayProxyRequestEvent()
                        .withQueryStringParameters(
                                Map.of(
                                        "fromDate", "2025-09-15T12:45+01:00",
                                        "toDate", "2025-09-15T13:15+01:00",
                                        "limit", "2"));

        when(mockLogsClient.startQuery(any()))
                .thenReturn(new StartQueryResult().withQueryId(TEST_QUERY_ID));
        when(mockLogsClient.getQueryResults(
                        new GetQueryResultsRequest().withQueryId(TEST_QUERY_ID)))
                .thenReturn(new GetQueryResultsResult().withStatus("Running"))
                .thenReturn(new GetQueryResultsResult().withStatus("Failed"));

        // Act
        var response = handler.handleRequest(request, mockContext);

        // Assert
        assertEquals(500, response.getStatusCode());
        assertEquals("{\"message\": \"Internal Server Error\"}", response.getBody());
    }

    @Test
    void handlerShouldThrowWhenReachedMaximumAttempts() {
        // Arrange
        APIGatewayProxyRequestEvent request =
                new APIGatewayProxyRequestEvent()
                        .withQueryStringParameters(
                                Map.of(
                                        "fromDate", "2025-09-15T12:45+01:00",
                                        "toDate", "2025-09-15T13:15+01:00",
                                        "limit", "2"));

        when(mockLogsClient.startQuery(any()))
                .thenReturn(new StartQueryResult().withQueryId(TEST_QUERY_ID));
        when(mockLogsClient.getQueryResults(
                        new GetQueryResultsRequest().withQueryId(TEST_QUERY_ID)))
                .thenReturn(new GetQueryResultsResult().withStatus("Running"))
                .thenReturn(new GetQueryResultsResult().withStatus("Running"))
                .thenReturn(new GetQueryResultsResult().withStatus("Running"))
                .thenReturn(new GetQueryResultsResult().withStatus("Running"))
                .thenReturn(new GetQueryResultsResult().withStatus("Running"))
                .thenReturn(new GetQueryResultsResult().withStatus("Running"))
                .thenReturn(new GetQueryResultsResult().withStatus("Running"))
                .thenReturn(new GetQueryResultsResult().withStatus("Running"))
                .thenReturn(new GetQueryResultsResult().withStatus("Running"))
                .thenReturn(new GetQueryResultsResult().withStatus("Running"))
                .thenReturn(new GetQueryResultsResult().withStatus("Running"));

        // Act
        var response = handler.handleRequest(request, mockContext);

        // Assert
        assertEquals(500, response.getStatusCode());
        assertEquals("{\"message\": \"Internal Server Error\"}", response.getBody());
    }

    @Test
    void shouldReturn404IfNoDataWasFound() {
        // Arrange
        var request =
                new APIGatewayProxyRequestEvent()
                        .withQueryStringParameters(
                                Map.of(
                                        "fromDate", "2025-09-15T12:45+01:00",
                                        "toDate", "2025-09-15T13:15+01:00",
                                        "limit", "2"));

        when(mockLogsClient.startQuery(any()))
                .thenReturn(new StartQueryResult().withQueryId(TEST_QUERY_ID));
        when(mockLogsClient.getQueryResults(
                        new GetQueryResultsRequest().withQueryId(TEST_QUERY_ID)))
                .thenReturn(new GetQueryResultsResult().withStatus("Running"))
                .thenReturn(
                        new GetQueryResultsResult().withStatus("Complete").withResults(List.of()));

        // Act
        var response = handler.handleRequest(request, mockContext);

        // Assert
        assertEquals(404, response.getStatusCode());
    }
}
