package uk.gov.di.ipv.core.fetchjourneytransitions;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.logs.AWSLogs;
import com.amazonaws.services.logs.AWSLogsClientBuilder;
import com.amazonaws.services.logs.model.*;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.lambda.powertools.logging.Logging;
import software.amazon.lambda.powertools.metrics.Metrics;
import uk.gov.di.ipv.core.fetchjourneytransitions.domain.Request;

import java.time.Instant;
import java.util.*;

public class FetchJourneyTransitionsHandler
        implements RequestHandler<
                Request, Map<String, Map<String, Map<String, Map<String, Integer>>>>> {
    private static final Logger LOGGER = LogManager.getLogger();

    private static final String LOG_GROUP =
            "/aws/ecs/your-log-group"; // Replace with your actual log group
    private static final String FIXED_QUERY =
            """
        fields @timestamp, @message
        | filter journeyEngine = "State transition"
        | stats count() as transitions by fromJourney, from, toJourney, to
        | limit 1000
    """;

    private final AWSLogs logsClient = AWSLogsClientBuilder.defaultClient();

    @Override
    @Logging(clearState = true)
    @Metrics(captureColdStart = true)
    public Map<String, Map<String, Map<String, Map<String, Integer>>>> handleRequest(
            Request input, Context context) {
        try {
            int minutes = input.minutes();
            long endTime = Instant.now().getEpochSecond();
            long startTime = endTime - (minutes * 60L);

            StartQueryRequest startQueryRequest =
                    new StartQueryRequest()
                            .withLogGroupName(LOG_GROUP)
                            .withQueryString(FIXED_QUERY)
                            .withStartTime(startTime)
                            .withEndTime(endTime);

            StartQueryResult startQueryResult = logsClient.startQuery(startQueryRequest);
            String queryId = startQueryResult.getQueryId();

            GetQueryResultsResult queryResults;
            do {
                Thread.sleep(1000);
                queryResults =
                        logsClient.getQueryResults(
                                new GetQueryResultsRequest().withQueryId(queryId));
            } while (!"Complete".equals(queryResults.getStatus()));

            Map<String, Map<String, Map<String, Map<String, Integer>>>> output = new HashMap<>();

            for (List<ResultField> row : queryResults.getResults()) {
                String fromJourney = null;
                String from = null;
                String toJourney = null;
                String to = null;
                Integer transitions = null;

                for (ResultField field : row) {
                    switch (field.getField()) {
                        case "fromJourney" -> fromJourney = field.getValue();
                        case "from" -> from = field.getValue();
                        case "toJourney" -> toJourney = field.getValue();
                        case "to" -> to = field.getValue();
                        case "transitions" -> transitions = Integer.parseInt(field.getValue());
                    }
                }

                if (fromJourney != null
                        && from != null
                        && toJourney != null
                        && to != null
                        && transitions != null) {
                    output.computeIfAbsent(fromJourney, k -> new HashMap<>())
                            .computeIfAbsent(from, k -> new HashMap<>())
                            .computeIfAbsent(toJourney, k -> new HashMap<>())
                            .put(to, transitions);
                }
            }

            return output;

        } catch (Exception e) {
            LOGGER.error("Unhandled lambda exception", e);
            throw new RuntimeException(e);
        }
    }
}
