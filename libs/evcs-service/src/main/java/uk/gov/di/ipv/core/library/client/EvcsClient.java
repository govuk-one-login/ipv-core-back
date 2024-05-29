package uk.gov.di.ipv.core.library.client;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.util.CollectionUtils;
import org.apache.http.client.utils.URIBuilder;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.lambda.powertools.tracing.Tracing;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.dto.EvcsCreateUserVCsDto;
import uk.gov.di.ipv.core.library.dto.EvcsGetUserVCsDto;
import uk.gov.di.ipv.core.library.dto.EvcsUpdateUserVCsDto;
import uk.gov.di.ipv.core.library.enums.EvcsVCState;
import uk.gov.di.ipv.core.library.exception.EvcsServiceException;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.service.ConfigService;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.List;
import java.util.stream.Collectors;

import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.EVCS_APPLICATION_URL;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.EVCS_APP_ID;

public class EvcsClient {
    private static final Logger LOGGER = LogManager.getLogger();
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    public static final String X_API_KEY_HEADER = "x-api-key";
    public static final String AUTHORISATION_HEADER_KEY = "Authorisation";
    public static final String VC_STATE_PARAM = "state";
    public static final String APPLICATION_JSON_CHARSET_UTF_8 = "application/json; charset=utf-8";
    public static final String CONTENT_TYPE = "Content-Type";

    private final HttpClient httpClient;
    private final ConfigService configService;

    @ExcludeFromGeneratedCoverageReport
    public EvcsClient(ConfigService configService) {
        this.configService = configService;
        this.httpClient = HttpClient.newHttpClient();
    }

    public EvcsClient(ConfigService configService, HttpClient httpClient) {
        this.configService = configService;
        this.httpClient = httpClient;
    }

    @Tracing
    public EvcsGetUserVCsDto getUserVcs(
            String userId, String evcsAccessToken, List<EvcsVCState> vcStatesToQueryFor)
            throws EvcsServiceException {
        try {
            HttpRequest.Builder httpRequestBuilder =
                    HttpRequest.newBuilder().uri(getUri(userId, vcStatesToQueryFor)).GET();
            httpRequestBuilder.header(
                    X_API_KEY_HEADER, configService.getAppApiKey(EVCS_APP_ID.getPath()));
            httpRequestBuilder.header(AUTHORISATION_HEADER_KEY, "Bearer " + evcsAccessToken);
            httpRequestBuilder.header(CONTENT_TYPE, APPLICATION_JSON_CHARSET_UTF_8);

            var evcsHttpResponse = sendHttpRequest(httpRequestBuilder.build());
            checkResponseStatusCode(evcsHttpResponse);

            EvcsGetUserVCsDto evcsGetUserVCs =
                    OBJECT_MAPPER.readValue(evcsHttpResponse.body(), new TypeReference<>() {});

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

    @Tracing
    public void createEvcsUserVCs(String userId, List<EvcsCreateUserVCsDto> userVCsForEvcs)
            throws EvcsServiceException {
        try {
            HttpRequest.Builder httpRequestBuilder =
                    HttpRequest.newBuilder()
                            .uri(getUri(userId, null))
                            .POST(
                                    HttpRequest.BodyPublishers.ofString(
                                            OBJECT_MAPPER.writeValueAsString(userVCsForEvcs)));
            httpRequestBuilder.header(
                    X_API_KEY_HEADER, configService.getAppApiKey(EVCS_APP_ID.getPath()));
            httpRequestBuilder.header(CONTENT_TYPE, APPLICATION_JSON_CHARSET_UTF_8);

            var evcsHttpResponse = sendHttpRequest(httpRequestBuilder.build());
            checkResponseStatusCode(evcsHttpResponse);
        } catch (URISyntaxException e) {
            throw new EvcsServiceException(
                    HTTPResponse.SC_SERVER_ERROR, ErrorResponse.FAILED_TO_CONSTRUCT_EVCS_URI);
        } catch (JsonProcessingException e) {
            throw new EvcsServiceException(
                    HTTPResponse.SC_SERVER_ERROR, ErrorResponse.FAILED_TO_PARSE_EVCS_REQUEST_BODY);
        }
    }

    @Tracing
    public void updateEvcsUserVCs(String userId, List<EvcsUpdateUserVCsDto> evcsUserVCsToUpdate)
            throws EvcsServiceException {
        try {
            HttpRequest.Builder httpRequestBuilder =
                    HttpRequest.newBuilder()
                            .uri(getUri(userId, null))
                            .method(
                                    "PATCH",
                                    HttpRequest.BodyPublishers.ofString(
                                            OBJECT_MAPPER.writeValueAsString(evcsUserVCsToUpdate)));
            httpRequestBuilder.header(
                    X_API_KEY_HEADER, configService.getAppApiKey(EVCS_APP_ID.getPath()));
            httpRequestBuilder.header(CONTENT_TYPE, APPLICATION_JSON_CHARSET_UTF_8);

            var evcsHttpResponse = sendHttpRequest(httpRequestBuilder.build());
            checkResponseStatusCode(evcsHttpResponse);
        } catch (URISyntaxException e) {
            throw new EvcsServiceException(
                    HTTPResponse.SC_SERVER_ERROR, ErrorResponse.FAILED_TO_CONSTRUCT_EVCS_URI);
        } catch (JsonProcessingException e) {
            throw new EvcsServiceException(
                    HTTPResponse.SC_SERVER_ERROR, ErrorResponse.FAILED_TO_PARSE_EVCS_REQUEST_BODY);
        }
    }

    private URI getUri(String userId, List<EvcsVCState> vcStatesToQueryFor)
            throws URISyntaxException {
        if (vcStatesToQueryFor != null) {
            return new URIBuilder(
                            configService
                                    .getSsmParameter(EVCS_APPLICATION_URL)
                                    .concat("/")
                                    .concat(userId))
                    .addParameter(
                            VC_STATE_PARAM,
                            vcStatesToQueryFor.stream()
                                    .map(EvcsVCState::name)
                                    .collect(Collectors.joining(",")))
                    .build();
        } else {
            return new URIBuilder(
                            configService
                                    .getSsmParameter(EVCS_APPLICATION_URL)
                                    .concat("/")
                                    .concat(userId))
                    .build();
        }
    }

    private void checkResponseStatusCode(HttpResponse<String> evcsHttpResponse)
            throws EvcsServiceException {
        if (200 > evcsHttpResponse.statusCode() || evcsHttpResponse.statusCode() > 299) {
            throw new EvcsServiceException(
                    HTTPResponse.SC_SERVER_ERROR,
                    ErrorResponse.RECEIVED_NON_200_RESPONSE_STATUS_CODE);
        }
        LOGGER.info(LogHelper.buildLogMessage("Successful HTTP response from EVCS Api"));
    }

    @Tracing
    private HttpResponse<String> sendHttpRequest(HttpRequest evcsHttpRequest)
            throws EvcsServiceException {
        LOGGER.info(LogHelper.buildLogMessage("Sending HTTP request to EVCS"));
        try {
            return httpClient.send(evcsHttpRequest, HttpResponse.BodyHandlers.ofString());
        } catch (IOException | InterruptedException e) {
            if (e instanceof InterruptedException) {
                // This should never happen running in Lambda as it's single threaded.
                Thread.currentThread().interrupt();
            }
            LOGGER.error(
                    LogHelper.buildErrorMessage(
                            ErrorResponse.FAILED_AT_EVCS_HTTP_REQUEST_SEND.getMessage(), e));
            throw new EvcsServiceException(
                    HTTPResponse.SC_SERVER_ERROR, ErrorResponse.FAILED_AT_EVCS_HTTP_REQUEST_SEND);
        }
    }
}
