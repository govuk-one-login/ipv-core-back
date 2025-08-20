package uk.gov.di.ipv.core.fetchjourneytransitions;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.logs.AWSLogs;
import com.amazonaws.services.logs.model.*;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.fetchjourneytransitions.domain.TransitionCount;

import java.util.List;
import java.util.Map;

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

    @Mock private AWSLogs mockLogsClient;
    @Mock private Context mockContext;
    private FetchJourneyTransitionsHandler handler;

    @BeforeEach
    void setup() {
        handler =
                new FetchJourneyTransitionsHandler() {
                    @Override
                    protected AWSLogs getLogsClient() {
                        return mockLogsClient;
                    }
                };
    }

    @Test
    void handlerShouldReturnJourneyTransitions() throws Exception {
        // Arrange
        APIGatewayProxyRequestEvent request =
                new APIGatewayProxyRequestEvent()
                        .withQueryStringParameters(Map.of("minutes", "30", "limit", "2"));

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
}
