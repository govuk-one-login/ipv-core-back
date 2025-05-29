package uk.gov.di.ipv.core.library.ais.client;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.hc.core5.http.ContentType;
import org.apache.hc.core5.net.URIBuilder;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.ipv.core.library.ais.dto.AccountInterventionStatusDto;
import uk.gov.di.ipv.core.library.ais.exception.AisClientException;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.exceptions.NonRetryableException;
import uk.gov.di.ipv.core.library.exceptions.RetryableException;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.retry.Retry;
import uk.gov.di.ipv.core.library.retry.Sleeper;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.tracing.TracingHttpClient;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.apache.hc.core5.http.HttpHeaders.CONTENT_TYPE;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.AIS_API_BASE_URL;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_RESPONSE_MESSAGE;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_STATUS_CODE;

public class AisClient {
    private static final Logger LOGGER = LogManager.getLogger();
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final List<Integer> RETRYABLE_STATUS_CODES = List.of(408, 429, 500, 503, 504);
    private static final int NUMBER_OF_HTTP_REQUEST_ATTEMPTS = 4;
    private static final int RETRY_DELAY_MILLIS = 1000;
    private final HttpClient httpClient;
    private final ConfigService configService;
    private final Sleeper sleeper;

    @ExcludeFromGeneratedCoverageReport
    public AisClient(ConfigService configService) {
        this.configService = configService;
        this.httpClient = TracingHttpClient.newHttpClient();
        this.sleeper = new Sleeper();
    }

    @ExcludeFromGeneratedCoverageReport
    public AisClient(ConfigService configService, HttpClient httpClient, Sleeper sleeper) {
        this.configService = configService;
        this.httpClient = httpClient;
        this.sleeper = sleeper;
    }

    public AccountInterventionStatusDto getAccountInterventionStatus(String userId)
            throws AisClientException {

        try {
            HttpRequest.Builder httpRequestBuilder =
                    HttpRequest.newBuilder()
                            .uri(getUri(userId))
                            .GET()
                            .header(CONTENT_TYPE, ContentType.APPLICATION_JSON.toString());

            var response = sendHttpRequest(httpRequestBuilder.build());
            return OBJECT_MAPPER.readValue(response.body(), AccountInterventionStatusDto.class);
        } catch (JsonProcessingException e) {
            throw new AisClientException("Failed parse AIS response body", e);
        }
    }

    private URI getUri(String userId) throws AisClientException {
        try {
            var baseUri =
                    "%s/ais/%s"
                            .formatted(
                                    configService.getParameter(AIS_API_BASE_URL),
                                    URLEncoder.encode(userId, StandardCharsets.UTF_8));
            var uriBuilder = new URIBuilder(baseUri);
            return uriBuilder.build();
        } catch (URISyntaxException e) {
            throw new AisClientException("Failed to construct AIS URL", e);
        }
    }

    private HttpResponse<String> sendHttpRequest(HttpRequest aisHttpRequest)
            throws AisClientException {

        try {
            return Retry.runTaskWithBackoff(
                    sleeper,
                    NUMBER_OF_HTTP_REQUEST_ATTEMPTS,
                    RETRY_DELAY_MILLIS,
                    () -> {
                        LOGGER.info(LogHelper.buildLogMessage("Sending HTTP request to AIS"));
                        try {
                            var response =
                                    httpClient.send(
                                            aisHttpRequest, HttpResponse.BodyHandlers.ofString());
                            checkResponseStatusCode(response);
                            return response;
                        } catch (IOException e) {
                            LOGGER.warn(
                                    LogHelper.buildErrorMessage(
                                            "IOException caught when sending request to AIS", e));
                            // The httpClient will retry IOExceptions that can be retried
                            throw new NonRetryableException(e);
                        } catch (InterruptedException e) {
                            // This should never happen running in Lambda as it's single
                            // threaded.
                            Thread.currentThread().interrupt();
                            throw new NonRetryableException(e);
                        }
                    });
        } catch (InterruptedException e) {
            // This should never happen running in Lambda as it's single threaded.
            Thread.currentThread().interrupt();
            LOGGER.error(
                    LogHelper.buildErrorMessage("Failed while sending http request to AIS", e));
            throw new AisClientException("Thread interrupted", e);
        } catch (NonRetryableException e) {
            LOGGER.error(
                    LogHelper.buildErrorMessage("Failed while sending http request to AIS", e));
            throw new AisClientException("Failed while sending http request to AIS", e);
        }
    }

    private void checkResponseStatusCode(HttpResponse<String> aisHttpResponse)
            throws RetryableException, NonRetryableException {
        var statusCode = aisHttpResponse.statusCode();

        if (statusCode < 200 || statusCode > 299) {
            String responseMessage;
            try {
                Map<String, String> responseBody =
                        OBJECT_MAPPER.readValue(aisHttpResponse.body(), new TypeReference<>() {});
                responseMessage =
                        Optional.ofNullable(responseBody.get("message"))
                                .orElse("Received no AIS response body.");
            } catch (JsonProcessingException e) {
                responseMessage = "Failed to parse AIS response body.";
            }

            LOGGER.error(
                    LogHelper.buildLogMessage("Received HTTP failure code from AIS")
                            .with(LOG_STATUS_CODE.getFieldName(), statusCode)
                            .with(LOG_RESPONSE_MESSAGE.getFieldName(), responseMessage));

            if (RETRYABLE_STATUS_CODES.contains(statusCode)) {
                throw new RetryableException("Received non-fatal HTTP failure code from AIS");
            }
            throw new NonRetryableException("Received fatal HTTP failure code from AIS");
        }
        LOGGER.info(LogHelper.buildLogMessage("Successful HTTP response from AIS"));
    }
}
