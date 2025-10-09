package uk.gov.di.ipv.core.library.sis.client;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.hc.core5.http.ContentType;
import org.apache.hc.core5.http.HttpStatus;
import org.apache.hc.core5.net.URIBuilder;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.enums.Vot;
import uk.gov.di.ipv.core.library.exceptions.NonRetryableException;
import uk.gov.di.ipv.core.library.exceptions.RetryableException;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.retry.Retry;
import uk.gov.di.ipv.core.library.retry.Sleeper;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.sis.dto.SisStoredIdentityCheckDto;
import uk.gov.di.ipv.core.library.sis.dto.SisStoredIdentityRequestBody;
import uk.gov.di.ipv.core.library.sis.exception.SisServiceException;
import uk.gov.di.ipv.core.library.tracing.TracingHttpClient;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.apache.hc.core5.http.HttpHeaders.AUTHORIZATION;
import static org.apache.hc.core5.http.HttpHeaders.CONTENT_TYPE;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.SIS_API_KEY;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_RESPONSE_MESSAGE;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_STATUS_CODE;

public class SisClient {
    public static final String X_API_KEY_HEADER = "x-api-key";
    private static final String USER_IDENTITY_SUB_PATH = "user-identity";
    private static final Logger LOGGER = LogManager.getLogger();
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final List<Integer> RETRYABLE_STATUS_CODES = List.of(401, 429);
    private static final int NUMBER_OF_HTTP_REQUEST_ATTEMPTS = 4;
    private static final int RETRY_DELAY_MILLIS = 1000;
    private final HttpClient httpClient;
    private final ConfigService configService;
    private final Sleeper sleeper;

    @ExcludeFromGeneratedCoverageReport
    public SisClient(ConfigService configService) {
        this.configService = configService;
        this.httpClient = TracingHttpClient.newHttpClient();
        this.sleeper = new Sleeper();
    }

    @ExcludeFromGeneratedCoverageReport
    public SisClient(ConfigService configService, HttpClient httpClient, Sleeper sleeper) {
        this.configService = configService;
        this.httpClient = httpClient;
        this.sleeper = sleeper;
    }

    public SisGetStoredIdentityResult getStoredIdentity(
            String accessToken, List<Vot> vtr, String journeyId) {
        try {
            LOGGER.info(LogHelper.buildLogMessage("Retrieving existing stored identity from SIS."));

            var requestBody = new SisStoredIdentityRequestBody(vtr, journeyId);

            HttpRequest.Builder httpRequestBuilder =
                    HttpRequest.newBuilder()
                            .uri(getUri(USER_IDENTITY_SUB_PATH))
                            .POST(
                                    HttpRequest.BodyPublishers.ofString(
                                            OBJECT_MAPPER.writeValueAsString(requestBody)))
                            .header(AUTHORIZATION, "Bearer " + accessToken)
                            .header(CONTENT_TYPE, ContentType.APPLICATION_JSON.toString())
                            .header(X_API_KEY_HEADER, configService.getSecret(SIS_API_KEY));

            var httpResponse = sendHttpRequest(httpRequestBuilder.build());

            if (httpResponse.statusCode() == HttpStatus.SC_NOT_FOUND) {
                LOGGER.info(LogHelper.buildLogMessage("Stored identity not found in SIS."));
                return new SisGetStoredIdentityResult(true, false, null);
            }

            SisStoredIdentityCheckDto identity = parseIdentity(httpResponse.body());
            if (identity == null) {
                return new SisGetStoredIdentityResult(false, false, null);
            }

            return new SisGetStoredIdentityResult(true, true, identity);
        } catch (Exception e) {
            LOGGER.error(
                    LogHelper.buildErrorMessage(
                            "Exception caught whilst getting identity from SIS", e));
            return new SisGetStoredIdentityResult(false, false, null);
        }
    }

    private SisStoredIdentityCheckDto parseIdentity(String json) {
        try {
            return OBJECT_MAPPER.readValue(json, SisStoredIdentityCheckDto.class);
        } catch (JsonProcessingException e) {
            LOGGER.error(
                    LogHelper.buildErrorMessage(
                            "Exception caught processing JSON from SIS: " + json, e));
            return null;
        }
    }

    private URI getUri(String subPath) throws URISyntaxException {
        var baseUri = "%s/%s".formatted(configService.getSisApplicationUrl(), subPath);

        var uriBuilder = new URIBuilder(baseUri);

        return uriBuilder.build();
    }

    private HttpResponse<String> sendHttpRequest(HttpRequest httpRequest)
            throws SisServiceException {

        try {
            return Retry.runTaskWithBackoff(
                    sleeper,
                    NUMBER_OF_HTTP_REQUEST_ATTEMPTS,
                    RETRY_DELAY_MILLIS,
                    () -> {
                        LOGGER.info(LogHelper.buildLogMessage("Sending HTTP request to SIS"));
                        try {
                            var res =
                                    httpClient.send(
                                            httpRequest, HttpResponse.BodyHandlers.ofString());
                            checkResponseStatusCode(res);
                            return res;
                        } catch (SisServiceException | IOException e) {
                            throw new NonRetryableException(e);
                        } catch (InterruptedException e) {
                            // This should never happen running in Lambda as it's single
                            // threaded.
                            Thread.currentThread().interrupt();
                            throw new NonRetryableException(e);
                        }
                    });
        } catch (NonRetryableException | InterruptedException e) {
            if (e instanceof InterruptedException) {
                // This should never happen running in Lambda as it's single threaded.
                Thread.currentThread().interrupt();
            } else if (e.getCause() instanceof SisServiceException sisException) {
                LOGGER.error(
                        LogHelper.buildErrorMessage(
                                "Failed sending HTTP request to SIS", sisException));
                throw sisException;
            }
            LOGGER.error(LogHelper.buildErrorMessage("Failed sending HTTP request to SIS", e));
            throw new SisServiceException("Failed sending HTTP request to SIS");
        }
    }

    private void checkResponseStatusCode(HttpResponse<String> sisHttpResponse)
            throws RetryableException, SisServiceException {
        var statusCode = sisHttpResponse.statusCode();

        // 404 is valid and indicates no identity was found
        if (statusCode >= HttpStatus.SC_MULTIPLE_CHOICES && statusCode != HttpStatus.SC_NOT_FOUND) {
            String responseMessage;
            try {
                Map<String, String> responseBody =
                        OBJECT_MAPPER.readValue(sisHttpResponse.body(), new TypeReference<>() {});
                responseMessage =
                        Optional.ofNullable(responseBody.get("message"))
                                .orElse("Received no sis response body.");
            } catch (JsonProcessingException e) {
                responseMessage = "Failed to parse sis response body.";
            }

            LOGGER.error(
                    LogHelper.buildLogMessage(
                                    ErrorResponse.RECEIVED_NON_200_RESPONSE_STATUS_CODE
                                            .getMessage())
                            .with(LOG_STATUS_CODE.getFieldName(), statusCode)
                            .with(LOG_RESPONSE_MESSAGE.getFieldName(), responseMessage));

            var e = new SisServiceException("Received non-200 status code from SIS: " + statusCode);

            if (RETRYABLE_STATUS_CODES.contains(statusCode)) {
                throw new RetryableException(e);
            }
            throw e;
        }
        LOGGER.info(LogHelper.buildLogMessage("Successful HTTP response from SIS Api"));
    }
}
