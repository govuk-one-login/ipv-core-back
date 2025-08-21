package uk.gov.di.ipv.core.fetchjourneytransitions;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyRequestEvent;
import com.amazonaws.services.lambda.runtime.events.APIGatewayProxyResponseEvent;
import com.amazonaws.services.logs.AWSLogs;
import com.amazonaws.services.logs.AWSLogsClientBuilder;
import com.amazonaws.services.logs.model.*;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.lambda.powertools.logging.Logging;
import software.amazon.lambda.powertools.metrics.Metrics;
import uk.gov.di.ipv.core.fetchjourneytransitions.domain.Request;
import uk.gov.di.ipv.core.fetchjourneytransitions.domain.TransitionCount;
import uk.gov.di.ipv.core.fetchjourneytransitions.exceptions.FetchJourneyTransitionException;

import java.time.Instant;
import java.util.*;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

public class FetchJourneyTransitionsHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {
    private static final Logger LOGGER = LogManager.getLogger();
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final String LOG_GROUP = "/aws/lambda/process-journey-event-dev";
    private static final int MAX_ATTEMPTS = 10;
    private static final Pattern JOURNEY_ID_PATTERN = Pattern.compile("^[A-Za-z0-9_-]{43}$");
    private static final Map<String, String> CORS_HEADERS = Map.of(
            "Access-Control-Allow-Origin", "*",                        // or "http://localhost:3000"
            "Access-Control-Allow-Methods", "POST,OPTIONS",
            "Access-Control-Allow-Headers", "Content-Type,x-api-key"
    );

    private final AWSLogs logsClient = getLogsClient();

    protected AWSLogs getLogsClient() {
        return AWSLogsClientBuilder.defaultClient();
    }

    @Override
    @Logging(clearState = true)
    @Metrics(captureColdStart = true)
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent event, Context context) {
        try {
            Request input = parseRequest(event);
            long now = Instant.now().getEpochSecond();
            long startTime = now - input.minutes() * 60L;

            if (input.ipvSessionId() != null && !isValidIpvSessionId(input.ipvSessionId())) {
                throw new IllegalArgumentException("Invalid ipvSessionId format");
            }

            String query = buildQuery(input);
            LOGGER.info("Executing CloudWatch Logs query: {}", query);

            List<TransitionCount> results = executeCloudWatchQuery(query, startTime, now);

            return new APIGatewayProxyResponseEvent()
                    .withStatusCode(200)
                    .withHeaders(mergeHeaders(Map.of("Content-Type", "application/json")))
                    .withBody(OBJECT_MAPPER.writeValueAsString(results));
        } catch (InterruptedException e) {
            LOGGER.warn("Interrupted!", e);
            Thread.currentThread().interrupt();
            return new APIGatewayProxyResponseEvent()
                    .withStatusCode(500)
                    .withBody("{\"message\": \"Interrupted\"}");
        } catch (FetchJourneyTransitionException | JsonProcessingException e) {
            LOGGER.error("Unhandled exception", e);
            return new APIGatewayProxyResponseEvent()
                    .withStatusCode(500)
                    .withBody("{\"message\": \"Internal Server Error\"}");
        }
    }

    private Request parseRequest(APIGatewayProxyRequestEvent event) {
        Map<String, String> q =
                Optional.ofNullable(event.getQueryStringParameters()).orElse(Map.of());
        int minutes = parseIntOrDefault(q.get("minutes"), 60);
        int limit = parseIntOrDefault(q.get("limit"), 100);
        String ipvSessionId = q.get("ipvSessionId");
        return new Request(minutes, limit, ipvSessionId);
    }

    private int parseIntOrDefault(String value, int defaultVal) {
        try {
            return value != null ? Integer.parseInt(value) : defaultVal;
        } catch (NumberFormatException e) {
            return defaultVal;
        }
    }

    private boolean isValidIpvSessionId(String id) {
        return JOURNEY_ID_PATTERN.matcher(id).matches();
    }

    private String buildQuery(Request input) {
        String filter =
                input.ipvSessionId() != null
                        ? String.format("| filter ipvSessionId = '%s'%n", input.ipvSessionId())
                        : "";

        return String.format(
                """
            fields @timestamp, @message
            | parse @message '"from":"*"' as from
            | parse @message '"fromJourney":"*"' as fromJourney
            | parse @message '"to":"*"' as to
            | parse @message '"toJourney":"*"' as toJourney
            | parse @message '"journeyEngine":"*"' as journeyEngine
            | filter journeyEngine = "State transition"
            %s| stats count() as transitions by fromJourney, from, toJourney, to
            | limit %d
        """,
                filter, input.limit());
    }

    private List<TransitionCount> executeCloudWatchQuery(String query, long start, long end)
            throws InterruptedException, FetchJourneyTransitionException {
        StartQueryResult startResult =
                logsClient.startQuery(
                        new StartQueryRequest()
                                .withLogGroupName(LOG_GROUP)
                                .withQueryString(query)
                                .withStartTime(start)
                                .withEndTime(end));

        String queryId = startResult.getQueryId();
        GetQueryResultsResult results;

        int attempts = 0;
        while (attempts++ < MAX_ATTEMPTS) {
            Thread.sleep(1000);
            results = logsClient.getQueryResults(new GetQueryResultsRequest().withQueryId(queryId));
            String status = results.getStatus();

            if ("Complete".equals(status)) {
                return results.getResults().stream()
                        .map(this::parseResultRow)
                        .filter(Objects::nonNull)
                        .toList();
            }

            if ("Failed".equals(status) || "Cancelled".equals(status) || "Timeout".equals(status)) {
                throw new FetchJourneyTransitionException(
                        "CloudWatch query did not succeed: " + status);
            }
        }

        throw new FetchJourneyTransitionException(
                "CloudWatch query did not complete within max attempts");
    }

    private TransitionCount parseResultRow(List<ResultField> row) {
        Map<String, String> fields =
                row.stream()
                        .collect(Collectors.toMap(ResultField::getField, ResultField::getValue));

        try {
            return new TransitionCount(
                    fields.get("fromJourney"),
                    fields.get("from"),
                    fields.get("toJourney"),
                    fields.get("to"),
                    Integer.parseInt(fields.get("transitions")));
        } catch (Exception e) {
            LOGGER.warn("Skipping row due to missing/invalid data: {}", fields);
            return null;
        }
    }

    private Map<String, String> mergeHeaders(Map<String, String> extra) {
        Map<String, String> merged = new HashMap<>(CORS_HEADERS);
        merged.putAll(extra);
        return merged;
    }
}
