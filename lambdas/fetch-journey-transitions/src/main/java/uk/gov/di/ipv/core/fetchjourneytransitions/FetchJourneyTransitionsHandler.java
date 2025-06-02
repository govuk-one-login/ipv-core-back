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

    private static final String LOG_GROUP =
            "/aws/ecs/your-log-group"; // Replace with your actual log group
    private static final Pattern JOURNEY_ID_PATTERN = Pattern.compile("^[A-Za-z0-9_-]{43}$");

    private final AWSLogs logsClient = AWSLogsClientBuilder.defaultClient();

    @Override
    @Logging(clearState = true)
    @Metrics(captureColdStart = true)
    public List<TransitionCount> handleRequest(Request input, Context context) {
        try {
            int minutes = input.minutes();
            long endTime = Instant.now().getEpochSecond();
            long startTime = endTime - (minutes * 60L);

            var ipvSessionId = input.ipvSessionId();
            if (ipvSessionId != null & isValidIpvSessionId(ipvSessionId)) {
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
                    | parse @message '"ipvSessionId":"*"' as ipvSessionId
                    | filter journeyEngine = "State transition"
                    %s
                    | stats count() as transitions by fromJourney, from, toJourney, to
                    | limit %d
                """,
                            input.ipvSessionId() != null
                                    ? "| filter ipvSessionId = '" + input.ipvSessionId() + "'"
                                    : "",
                            input.limit());

            StartQueryRequest startQueryRequest =
                    new StartQueryRequest()
                            .withLogGroupName(LOG_GROUP)
                            .withQueryString(query)
                            .withStartTime(startTime)
                            .withEndTime(endTime);

            StartQueryResult startQueryResult = logsClient.startQuery(startQueryRequest);
            String queryId = startQueryResult.getQueryId();

            GetQueryResultsResult queryResults;
            do {
                queryResults =
                        logsClient.getQueryResults(
                                new GetQueryResultsRequest().withQueryId(queryId));
                Thread.sleep(1000);
            } while (!"Complete".equals(queryResults.getStatus()));

            List<TransitionCount> output = new ArrayList<>();

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
                    output.add(new TransitionCount(fromJourney, from, toJourney, to, transitions));
                }
            }

            return output;

        } catch (Exception e) {
            LOGGER.error("Unhandled lambda exception", e);
            throw new RuntimeException(e);
        }
    }

    private boolean isValidIpvSessionId(String id) {
        return JOURNEY_ID_PATTERN.matcher(id).matches();
    }
}
