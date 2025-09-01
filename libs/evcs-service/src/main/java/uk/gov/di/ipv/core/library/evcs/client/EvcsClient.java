package uk.gov.di.ipv.core.library.evcs.client;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.util.CollectionUtils;
import com.nimbusds.oauth2.sdk.util.StringUtils;
import org.apache.hc.core5.http.ContentType;
import org.apache.hc.core5.net.URIBuilder;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.evcs.dto.EvcsCreateUserVCsDto;
import uk.gov.di.ipv.core.library.evcs.dto.EvcsGetUserVCsDto;
import uk.gov.di.ipv.core.library.evcs.dto.EvcsInvalidateStoredIdentityDto;
import uk.gov.di.ipv.core.library.evcs.dto.EvcsPostIdentityDto;
import uk.gov.di.ipv.core.library.evcs.dto.EvcsUpdateUserVCsDto;
import uk.gov.di.ipv.core.library.evcs.enums.EvcsVCState;
import uk.gov.di.ipv.core.library.evcs.exception.EvcsServiceException;
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
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

import static org.apache.hc.core5.http.HttpHeaders.AUTHORIZATION;
import static org.apache.hc.core5.http.HttpHeaders.CONTENT_TYPE;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.EVCS_APPLICATION_URL;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_RESPONSE_MESSAGE;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_STATUS_CODE;

public class EvcsClient {
    public static final String X_API_KEY_HEADER = "x-api-key";
    public static final String VC_STATE_PARAM = "state";
    public static final String AFTER_KEY_PARAM = "afterKey";
    private static final String VCS_SUB_PATH = "vcs";
    private static final String IDENTITY_SUB_PATH = "identity";
    private static final Logger LOGGER = LogManager.getLogger();
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final List<Integer> RETRYABLE_STATUS_CODES = List.of(401, 429);
    private static final int NUMBER_OF_HTTP_REQUEST_ATTEMPTS = 4;
    private static final int RETRY_DELAY_MILLIS = 1000;
    private final HttpClient httpClient;
    private final ConfigService configService;
    private final Sleeper sleeper;

    @ExcludeFromGeneratedCoverageReport
    public EvcsClient(ConfigService configService) {
        this.configService = configService;
        this.httpClient = TracingHttpClient.newHttpClient();
        this.sleeper = new Sleeper();
    }

    @ExcludeFromGeneratedCoverageReport
    public EvcsClient(ConfigService configService, HttpClient httpClient, Sleeper sleeper) {
        this.configService = configService;
        this.httpClient = httpClient;
        this.sleeper = sleeper;
    }

    public EvcsGetUserVCsDto getUserVcs(
            String userId, String evcsAccessToken, List<EvcsVCState> vcStatesToQueryFor)
            throws EvcsServiceException {
        LOGGER.info(LogHelper.buildLogMessage("Retrieving existing user VCs from Evcs."));

        var apiKey = configService.getSecret(ConfigurationVariable.EVCS_API_KEY);
        var evcsGetUserVcsDto =
                attemptGetUserVcsRequest(userId, apiKey, evcsAccessToken, vcStatesToQueryFor, null);
        var evcsUserVcs = new java.util.ArrayList<>(evcsGetUserVcsDto.vcs());

        try {
            var afterKey = evcsGetUserVcsDto.afterKey();
            int attemptCount = 0;
            final int maxAttempts = 100;

            while (!StringUtils.isBlank(afterKey) && attemptCount < maxAttempts) {
                attemptCount++;
                LOGGER.info(
                        LogHelper.buildLogMessage(
                                "Attempt "
                                        + attemptCount
                                        + " to get additional user VCs from EVCS."));

                var additionalUserVcs =
                        attemptGetUserVcsRequest(
                                userId, apiKey, evcsAccessToken, vcStatesToQueryFor, afterKey);
                evcsUserVcs.addAll(additionalUserVcs.vcs());
                afterKey = additionalUserVcs.afterKey();
            }

            if (attemptCount >= maxAttempts) {
                LOGGER.warn(
                        LogHelper.buildLogMessage(
                                "Stopped retrieving additional VCs after reaching max attempt limit of "
                                        + maxAttempts));
            }

        } catch (EvcsServiceException e) {
            LOGGER.warn(
                    LogHelper.buildLogMessage(
                            "Failed to get the rest of the user's VCs with the afterKey."));
        }

        if (CollectionUtils.isEmpty(evcsUserVcs)) {
            LOGGER.info(LogHelper.buildLogMessage("No user VCs found in EVCS response"));
        }

        return new EvcsGetUserVCsDto(evcsUserVcs, null);
    }

    private EvcsGetUserVCsDto attemptGetUserVcsRequest(
            String userId,
            String apiKey,
            String evcsAccessToken,
            List<EvcsVCState> vcStatesToQueryFor,
            String afterKey)
            throws EvcsServiceException {
        try {
            HttpRequest.Builder httpRequestBuilder =
                    HttpRequest.newBuilder()
                            .uri(getUri(VCS_SUB_PATH, userId, vcStatesToQueryFor, afterKey))
                            .GET()
                            .header(X_API_KEY_HEADER, apiKey)
                            .header(AUTHORIZATION, "Bearer " + evcsAccessToken);

            var evcsHttpResponse = sendHttpRequest(httpRequestBuilder.build());

            EvcsGetUserVCsDto evcsGetUserVCs =
                    evcsHttpResponse.statusCode() != 404
                            ? OBJECT_MAPPER.readValue(
                                    evcsHttpResponse.body(), new TypeReference<>() {})
                            : new EvcsGetUserVCsDto(Collections.emptyList(), null);

            if (CollectionUtils.isEmpty(evcsGetUserVCs.vcs())) {
                LOGGER.info(LogHelper.buildLogMessage("No user VCs found in EVCS response"));
            }

            return evcsGetUserVCs;
        } catch (JsonProcessingException e) {
            throw new EvcsServiceException(
                    HTTPResponse.SC_SERVER_ERROR, ErrorResponse.FAILED_TO_PARSE_EVCS_RESPONSE);
        } catch (URISyntaxException e) {
            throw new EvcsServiceException(
                    HTTPResponse.SC_SERVER_ERROR, ErrorResponse.FAILED_TO_CONSTRUCT_EVCS_URI);
        }
    }

    public HttpResponse<String> storeUserVCs(
            String userId, List<EvcsCreateUserVCsDto> userVCsForEvcs) throws EvcsServiceException {
        LOGGER.info(
                LogHelper.buildLogMessage(
                        "Preparing to store %d user VCs using POST /vcs endpoint"
                                .formatted(userVCsForEvcs.size())));
        try {
            HttpRequest.Builder httpRequestBuilder =
                    HttpRequest.newBuilder()
                            .uri(getUri(VCS_SUB_PATH, userId, null))
                            .POST(
                                    HttpRequest.BodyPublishers.ofString(
                                            OBJECT_MAPPER.writeValueAsString(userVCsForEvcs)))
                            .header(
                                    X_API_KEY_HEADER,
                                    configService.getSecret(ConfigurationVariable.EVCS_API_KEY))
                            .header(CONTENT_TYPE, ContentType.APPLICATION_JSON.toString());

            return sendHttpRequest(httpRequestBuilder.build());
        } catch (URISyntaxException e) {
            throw new EvcsServiceException(
                    HTTPResponse.SC_SERVER_ERROR, ErrorResponse.FAILED_TO_CONSTRUCT_EVCS_URI);
        } catch (JsonProcessingException e) {
            throw new EvcsServiceException(
                    HTTPResponse.SC_SERVER_ERROR, ErrorResponse.FAILED_TO_PARSE_EVCS_REQUEST_BODY);
        }
    }

    public HttpResponse<String> storeUserIdentity(EvcsPostIdentityDto evcsPostIdentity)
            throws EvcsServiceException {
        LOGGER.info(LogHelper.buildLogMessage("Preparing to store user's stored identity record"));
        try {
            HttpRequest.Builder httpRequestBuilder =
                    HttpRequest.newBuilder()
                            .uri(getIdentityUri(null))
                            .POST(
                                    HttpRequest.BodyPublishers.ofString(
                                            OBJECT_MAPPER.writeValueAsString(evcsPostIdentity)))
                            .header(
                                    X_API_KEY_HEADER,
                                    configService.getSecret(ConfigurationVariable.EVCS_API_KEY))
                            .header(CONTENT_TYPE, ContentType.APPLICATION_JSON.toString());

            return sendHttpRequest(httpRequestBuilder.build());
        } catch (URISyntaxException e) {
            throw new EvcsServiceException(
                    HTTPResponse.SC_SERVER_ERROR, ErrorResponse.FAILED_TO_CONSTRUCT_EVCS_URI);
        } catch (JsonProcessingException e) {
            throw new EvcsServiceException(
                    HTTPResponse.SC_SERVER_ERROR, ErrorResponse.FAILED_TO_PARSE_EVCS_REQUEST_BODY);
        }
    }

    public HttpResponse<String> updateUserVCs(
            String userId, List<EvcsUpdateUserVCsDto> evcsUserVCsToUpdate)
            throws EvcsServiceException {
        LOGGER.info(
                LogHelper.buildLogMessage(
                        "Preparing to update %d user VCs".formatted(evcsUserVCsToUpdate.size())));
        try {
            HttpRequest.Builder httpRequestBuilder =
                    HttpRequest.newBuilder()
                            .uri(getUri(VCS_SUB_PATH, userId, null))
                            .method(
                                    "PATCH",
                                    HttpRequest.BodyPublishers.ofString(
                                            OBJECT_MAPPER.writeValueAsString(evcsUserVCsToUpdate)))
                            .header(
                                    X_API_KEY_HEADER,
                                    configService.getSecret(ConfigurationVariable.EVCS_API_KEY))
                            .header(CONTENT_TYPE, ContentType.APPLICATION_JSON.toString());

            return sendHttpRequest(httpRequestBuilder.build());
        } catch (URISyntaxException e) {
            throw new EvcsServiceException(
                    HTTPResponse.SC_SERVER_ERROR, ErrorResponse.FAILED_TO_CONSTRUCT_EVCS_URI);
        } catch (JsonProcessingException e) {
            throw new EvcsServiceException(
                    HTTPResponse.SC_SERVER_ERROR, ErrorResponse.FAILED_TO_PARSE_EVCS_REQUEST_BODY);
        }
    }

    public HttpResponse<String> invalidateStoredIdentityRecord(String userId)
            throws EvcsServiceException {
        LOGGER.info(
                LogHelper.buildLogMessage("Preparing to invalidate user's stored identity record"));
        try {
            HttpRequest.Builder httpRequestBuilder =
                    HttpRequest.newBuilder()
                            .uri(getIdentityUri("invalidate"))
                            .POST(
                                    HttpRequest.BodyPublishers.ofString(
                                            OBJECT_MAPPER.writeValueAsString(
                                                    new EvcsInvalidateStoredIdentityDto(userId))))
                            .header(
                                    X_API_KEY_HEADER,
                                    configService.getSecret(ConfigurationVariable.EVCS_API_KEY))
                            .header(CONTENT_TYPE, ContentType.APPLICATION_JSON.toString());

            return sendHttpRequest(httpRequestBuilder.build());
        } catch (URISyntaxException e) {
            throw new EvcsServiceException(
                    HTTPResponse.SC_SERVER_ERROR, ErrorResponse.FAILED_TO_CONSTRUCT_EVCS_URI);
        } catch (JsonProcessingException e) {
            throw new EvcsServiceException(
                    HTTPResponse.SC_SERVER_ERROR, ErrorResponse.FAILED_TO_PARSE_EVCS_REQUEST_BODY);
        }
    }

    private URI getIdentityUri(String path) throws URISyntaxException {
        var subPath =
                StringUtils.isBlank(path)
                        ? IDENTITY_SUB_PATH
                        : String.join("/", IDENTITY_SUB_PATH, path);
        return getUri(subPath, null, null);
    }

    private URI getUri(String subPath, String userId, List<EvcsVCState> vcStatesToQueryFor)
            throws URISyntaxException {
        return getUri(subPath, userId, vcStatesToQueryFor, null);
    }

    private URI getUri(
            String subPath, String userId, List<EvcsVCState> vcStatesToQueryFor, String afterKey)
            throws URISyntaxException {

        var baseUri = "%s/%s".formatted(configService.getParameter(EVCS_APPLICATION_URL), subPath);

        if (userId != null) {
            baseUri =
                    (baseUri + "/%s").formatted(URLEncoder.encode(userId, StandardCharsets.UTF_8));
        }

        var uriBuilder = new URIBuilder(baseUri);
        if (vcStatesToQueryFor != null) {
            uriBuilder.addParameter(
                    VC_STATE_PARAM,
                    vcStatesToQueryFor.stream()
                            .map(EvcsVCState::name)
                            .collect(Collectors.joining(",")));
        }

        if (afterKey != null) {
            uriBuilder.addParameter(AFTER_KEY_PARAM, afterKey);
        }
        return uriBuilder.build();
    }

    private void checkResponseStatusCode(HttpResponse<String> evcsHttpResponse)
            throws RetryableException, EvcsServiceException {
        var statusCode = evcsHttpResponse.statusCode();

        // 404 is valid and indicates the user has no VCs
        if (statusCode > 299 && statusCode != 404) {
            String responseMessage;
            try {
                Map<String, String> responseBody =
                        OBJECT_MAPPER.readValue(evcsHttpResponse.body(), new TypeReference<>() {});
                responseMessage =
                        Optional.ofNullable(responseBody.get("message"))
                                .orElse("Received no evcs response body.");
            } catch (JsonProcessingException e) {
                responseMessage = "Failed to parse evcs response body.";
            }

            LOGGER.error(
                    LogHelper.buildLogMessage(
                                    ErrorResponse.RECEIVED_NON_200_RESPONSE_STATUS_CODE
                                            .getMessage())
                            .with(LOG_STATUS_CODE.getFieldName(), statusCode)
                            .with(LOG_RESPONSE_MESSAGE.getFieldName(), responseMessage));

            var e =
                    new EvcsServiceException(
                            HTTPResponse.SC_SERVER_ERROR,
                            ErrorResponse.RECEIVED_NON_200_RESPONSE_STATUS_CODE);

            if (RETRYABLE_STATUS_CODES.contains(statusCode)) {
                throw new RetryableException(e);
            }
            throw e;
        }
        LOGGER.info(LogHelper.buildLogMessage("Successful HTTP response from EVCS Api"));
    }

    private HttpResponse<String> sendHttpRequest(HttpRequest evcsHttpRequest)
            throws EvcsServiceException {

        try {
            return Retry.runTaskWithBackoff(
                    sleeper,
                    NUMBER_OF_HTTP_REQUEST_ATTEMPTS,
                    RETRY_DELAY_MILLIS,
                    () -> {
                        LOGGER.info(LogHelper.buildLogMessage("Sending HTTP request to EVCS"));
                        try {
                            var res =
                                    httpClient.send(
                                            evcsHttpRequest, HttpResponse.BodyHandlers.ofString());
                            checkResponseStatusCode(res);
                            return res;
                        } catch (EvcsServiceException | IOException e) {
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
            } else if (e.getCause() instanceof EvcsServiceException evcsException) {
                LOGGER.error(
                        LogHelper.buildErrorMessage(
                                ErrorResponse.FAILED_AT_EVCS_HTTP_REQUEST_SEND.getMessage(),
                                evcsException));
                throw evcsException;
            }
            LOGGER.error(
                    LogHelper.buildErrorMessage(
                            ErrorResponse.FAILED_AT_EVCS_HTTP_REQUEST_SEND.getMessage(), e));
            throw new EvcsServiceException(
                    HTTPResponse.SC_SERVER_ERROR, ErrorResponse.FAILED_AT_EVCS_HTTP_REQUEST_SEND);
        }
    }
}
