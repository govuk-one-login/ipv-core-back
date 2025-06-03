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
import uk.gov.di.ipv.core.fetchjourneytransitions.domain.TransitionCount;

import java.time.Instant;
import java.util.*;
import java.util.regex.Pattern;

public class FetchJourneyTransitionsHandler
        implements RequestHandler<Request, List<TransitionCount>> {
    private static final Logger LOGGER = LogManager.getLogger();
    private static final String LOG_GROUP = "/aws/lambda/process-journey-event-dev";
    private static final Pattern JOURNEY_ID_PATTERN = Pattern.compile("^[A-Za-z0-9_-]{43}$");

    private final AWSLogs logsClient = AWSLogsClientBuilder.defaultClient();

    @Override
    @Logging(clearState = true)
    @Metrics(captureColdStart = true)
    public List<TransitionCount> handleRequest(Request input, Context context) {
        LOGGER.info("Handling request: {}", input);

        try {
            int minutes = input.minutes();
            LOGGER.info("Input minutes: {}", minutes);

            long endTime = Instant.now().getEpochSecond();
            LOGGER.info("Computed endTime (epoch seconds): {}", endTime);

            long startTime = endTime - (minutes * 60L);
            LOGGER.info("Computed startTime (epoch seconds): {}", startTime);

            var ipvSessionId = input.ipvSessionId();
            LOGGER.info("Input ipvSessionId: {}", ipvSessionId);

            if (ipvSessionId != null & isValidIpvSessionId(ipvSessionId)) {
                LOGGER.info("Invalid journey ID detected, throwing exception");
                throw new Exception("Invalid journey Id");
            }

            String query =
                    String.format(
                            """
                    fields @timestamp, @message
                    | parse @message '"from":"*"' as from
                    | parse @message '"fromJourney":"*"' as fromJourney
                    | parse @message '"to":"*"' as to
                    | parse @message '"toJourney":"*"' as toJourney
                    | parse @message '"journeyEngine":"*"' as journeyEngine
                    | filter journeyEngine = "State transition"
                    %s
                    | stats count() as transitions by fromJourney, from, toJourney, to
                    | limit %d
                """,
                            ipvSessionId != null
                                    ? "| filter ipvSessionId = '" + ipvSessionId + "'"
                                    : "",
                            input.limit());
            LOGGER.info("Constructed CloudWatch Logs Insights query:\n{}", query);

            StartQueryRequest startQueryRequest =
                    new StartQueryRequest()
                            .withLogGroupName(LOG_GROUP)
                            .withQueryString(query)
                            .withStartTime(startTime)
                            .withEndTime(endTime);
            LOGGER.info("StartQueryRequest prepared: {}", startQueryRequest);

            StartQueryResult startQueryResult = logsClient.startQuery(startQueryRequest);
            LOGGER.info("StartQueryResult received: {}", startQueryResult);

            String queryId = startQueryResult.getQueryId();
            LOGGER.info("Query ID: {}", queryId);

            GetQueryResultsResult queryResults;
            do {
                LOGGER.info("Polling for query results...");
                queryResults =
                        logsClient.getQueryResults(
                                new GetQueryResultsRequest().withQueryId(queryId));
                LOGGER.info("Query status: {}", queryResults.getStatus());
                Thread.sleep(1000);
            } while (!"Complete".equals(queryResults.getStatus()));

            LOGGER.info("Query complete. Processing results.");
            List<TransitionCount> output = new ArrayList<>();

            for (List<ResultField> row : queryResults.getResults()) {
                LOGGER.info("Processing result row: {}", row);

                String fromJourney = null;
                String from = null;
                String toJourney = null;
                String to = null;
                Integer transitions = null;

                for (ResultField field : row) {
                    LOGGER.info("ResultField: {}", field);
                    switch (field.getField()) {
                        case "fromJourney" -> fromJourney = field.getValue();
                        case "from" -> from = field.getValue();
                        case "toJourney" -> toJourney = field.getValue();
                        case "to" -> to = field.getValue();
                        case "transitions" -> transitions = Integer.parseInt(field.getValue());
                    }
                }

                LOGGER.info(
                        "Parsed - fromJourney: {}, from: {}, toJourney: {}, to: {}, transitions: {}",
                        fromJourney,
                        from,
                        toJourney,
                        to,
                        transitions);

                if (fromJourney != null
                        && from != null
                        && toJourney != null
                        && to != null
                        && transitions != null) {
                    TransitionCount transitionCount =
                            new TransitionCount(fromJourney, from, toJourney, to, transitions);
                    output.add(transitionCount);
                    LOGGER.info("Added TransitionCount: {}", transitionCount);
                } else {
                    LOGGER.info("Incomplete data row skipped");
                }
            }

            LOGGER.info("Final output size: {}", output.size());
            return output;

        } catch (Exception e) {
            LOGGER.error("Unhandled lambda exception", e);
            throw new RuntimeException(e);
        }
    }

    private boolean isValidIpvSessionId(String id) {
        LOGGER.info("Validating ipvSessionId: {}", id);
        boolean isValid = JOURNEY_ID_PATTERN.matcher(id).matches();
        LOGGER.info("Validation result: {}", isValid);
        return isValid;
    }
}
