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
import org.apache.http.HttpStatus;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.lambda.powertools.logging.Logging;
import software.amazon.lambda.powertools.metrics.Metrics;
import uk.gov.di.ipv.core.fetchjourneytransitions.domain.Request;
import uk.gov.di.ipv.core.fetchjourneytransitions.domain.TransitionCount;
import uk.gov.di.ipv.core.fetchjourneytransitions.exceptions.FetchJourneyTransitionException;
import uk.gov.di.ipv.core.fetchjourneytransitions.exceptions.RequestParseException;
import uk.gov.di.ipv.core.fetchjourneytransitions.helper.ValidationHelper;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

import java.time.OffsetDateTime;
import java.util.*;
import java.util.stream.Collectors;

public class FetchJourneyTransitionsHandler
        implements RequestHandler<APIGatewayProxyRequestEvent, APIGatewayProxyResponseEvent> {
    private static final Logger LOGGER = LogManager.getLogger();
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final String ENVIRONMENT =
            Optional.ofNullable(System.getenv("ENVIRONMENT")).orElse("build");
    private static final String LOG_GROUP =
            String.format("/aws/lambda/process-journey-event-%s", ENVIRONMENT);
    private static final int MAX_ATTEMPTS = 10;
    private static final Map<String, String> CORS_HEADERS =
            Map.of(
                    "Access-Control-Allow-Origin", "*",
                    "Access-Control-Allow-Methods", "POST,OPTIONS",
                    "Access-Control-Allow-Headers", "Content-Type,x-api-key");

    private final AWSLogs logsClient;

    @ExcludeFromGeneratedCoverageReport
    public FetchJourneyTransitionsHandler() {
        this.logsClient = AWSLogsClientBuilder.defaultClient();
    }

    @ExcludeFromGeneratedCoverageReport
    public FetchJourneyTransitionsHandler(AWSLogs logsClient) {
        this.logsClient = logsClient;
    }

    @Override
    @Logging(clearState = true)
    @Metrics(captureColdStart = true)
    public APIGatewayProxyResponseEvent handleRequest(
            APIGatewayProxyRequestEvent event, Context context) {
        try {
            var input = parseRequest(event);
            var query = buildQuery(input);
            LOGGER.info(
                    "Executing CloudWatch Logs query: {} in time window from: {} to: {}",
                    query,
                    input.fromDate(),
                    input.toDate());

            var results =
                    executeCloudWatchQuery(
                            query,
                            input.fromDate().getEpochSecond(),
                            input.toDate().getEpochSecond());

            if (results.isEmpty()) {
                return new APIGatewayProxyResponseEvent()
                        .withStatusCode(404)
                        .withBody(String.format("{\"message\": \"%s\"}", "Not found"));
            }

            return new APIGatewayProxyResponseEvent()
                    .withStatusCode(200)
                    .withHeaders(mergeHeaders(Map.of("Content-Type", "application/json")))
                    .withBody(OBJECT_MAPPER.writeValueAsString(results));
        } catch (RequestParseException e) {
            LOGGER.error("Invalid request", e);
            return new APIGatewayProxyResponseEvent()
                    .withStatusCode(HttpStatus.SC_BAD_REQUEST)
                    .withBody(String.format("{\"message\": \"%s\"}", e.getMessage()));
        } catch (InterruptedException e) {
            LOGGER.warn("Interrupted!", e);
            Thread.currentThread().interrupt();
            return new APIGatewayProxyResponseEvent()
                    .withStatusCode(HttpStatus.SC_INTERNAL_SERVER_ERROR)
                    .withBody("{\"message\": \"Interrupted\"}");
        } catch (FetchJourneyTransitionException | JsonProcessingException e) {
            LOGGER.error("Unhandled exception", e);
            return new APIGatewayProxyResponseEvent()
                    .withStatusCode(HttpStatus.SC_INTERNAL_SERVER_ERROR)
                    .withBody("{\"message\": \"Internal Server Error\"}");
        }
    }

    private Request parseRequest(APIGatewayProxyRequestEvent event) throws RequestParseException {
        Map<String, String> eventQueryParameters =
                Optional.ofNullable(event.getQueryStringParameters()).orElse(Map.of());
        var fromDate = OffsetDateTime.parse(eventQueryParameters.get("fromDate")).toInstant();
        var toDate = OffsetDateTime.parse(eventQueryParameters.get("toDate")).toInstant();
        var limit = ValidationHelper.parseIntOrDefault(eventQueryParameters.get("limit"), 100);
        var ipvSessionId = eventQueryParameters.get("ipvSessionId");
        var govukJourneyId = eventQueryParameters.get("govukJourneyId");
        return Request.create(fromDate, toDate, limit, ipvSessionId, govukJourneyId);
    }

    private String buildQuery(Request input) {
        var ipvSessionIdQuery = "| filter ipvSessionId = '%s'%n";
        var govukJourneyIdQuery = "| filter govuk_signin_journey_id = '%s'%n";

        var filter =
                Optional.ofNullable(input.ipvSessionId())
                        .map(id -> String.format(ipvSessionIdQuery, id))
                        .or(
                                () ->
                                        Optional.ofNullable(input.govukJourneyId())
                                                .map(id -> String.format(govukJourneyIdQuery, id)))
                        .orElse("");

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
