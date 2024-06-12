package uk.gov.di.ipv.core.library.client;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.util.CollectionUtils;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.entity.ContentType;
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
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

import static org.apache.http.HttpHeaders.AUTHORIZATION;
import static org.apache.http.HttpHeaders.CONTENT_TYPE;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.EVCS_APPLICATION_URL;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.EVCS_APP_ID;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_MESSAGE_DESCRIPTION;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_STATUS_CODE;

public class EvcsClient {
    private static final Logger LOGGER = LogManager.getLogger();
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    public static final String X_API_KEY_HEADER = "x-api-key";
    public static final String VC_STATE_PARAM = "state";

    private final HttpClient httpClient;
    private final ConfigService configService;

    @ExcludeFromGeneratedCoverageReport
    public EvcsClient(ConfigService configService) {
        this.configService = configService;
        this.httpClient = HttpClient.newHttpClient();
    }

    @ExcludeFromGeneratedCoverageReport
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
                    HttpRequest.newBuilder()
                            .uri(getUri(userId, vcStatesToQueryFor))
                            .GET()
                            .header(
                                    X_API_KEY_HEADER,
                                    configService.getAppApiKey(EVCS_APP_ID.getPath()))
                            .header(AUTHORIZATION, "Bearer " + evcsAccessToken);

            var evcsHttpResponse = sendHttpRequest(httpRequestBuilder.build());

            EvcsGetUserVCsDto evcsGetUserVCs =
                    evcsHttpResponse.statusCode() != 404
                            ? OBJECT_MAPPER.readValue(
                                    evcsHttpResponse.body(), new TypeReference<>() {})
                            : new EvcsGetUserVCsDto(Collections.emptyList());

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
    public void storeUserVCs(String userId, List<EvcsCreateUserVCsDto> userVCsForEvcs)
            throws EvcsServiceException {
        try {
            HttpRequest.Builder httpRequestBuilder =
                    HttpRequest.newBuilder()
                            .uri(getUri(userId, null))
                            .POST(
                                    HttpRequest.BodyPublishers.ofString(
                                            OBJECT_MAPPER.writeValueAsString(userVCsForEvcs)))
                            .header(
                                    X_API_KEY_HEADER,
                                    configService.getAppApiKey(EVCS_APP_ID.getPath()))
                            .header(CONTENT_TYPE, ContentType.APPLICATION_JSON.toString());

            sendHttpRequest(httpRequestBuilder.build());
        } catch (URISyntaxException e) {
            throw new EvcsServiceException(
                    HTTPResponse.SC_SERVER_ERROR, ErrorResponse.FAILED_TO_CONSTRUCT_EVCS_URI);
        } catch (JsonProcessingException e) {
            throw new EvcsServiceException(
                    HTTPResponse.SC_SERVER_ERROR, ErrorResponse.FAILED_TO_PARSE_EVCS_REQUEST_BODY);
        }
    }

    @Tracing
    public void updateUserVCs(String userId, List<EvcsUpdateUserVCsDto> evcsUserVCsToUpdate)
            throws EvcsServiceException {
        try {
            HttpRequest.Builder httpRequestBuilder =
                    HttpRequest.newBuilder()
                            .uri(getUri(userId, null))
                            .method(
                                    "PATCH",
                                    HttpRequest.BodyPublishers.ofString(
                                            OBJECT_MAPPER.writeValueAsString(evcsUserVCsToUpdate)))
                            .header(
                                    X_API_KEY_HEADER,
                                    configService.getAppApiKey(EVCS_APP_ID.getPath()))
                            .header(CONTENT_TYPE, ContentType.APPLICATION_JSON.toString());

            sendHttpRequest(httpRequestBuilder.build());
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
        URI evcsUri = new URI(configService.getSsmParameter(EVCS_APPLICATION_URL));
        List<String> pathSegments =
                evcsUri.getPath() != null
                        ? List.of(evcsUri.getPath().replaceFirst("/", ""), "vcs", userId)
                        : List.of("vcs", userId);
        var uriBuilder = new URIBuilder(evcsUri).setPathSegments(pathSegments);
        if (vcStatesToQueryFor != null) {
            uriBuilder.addParameter(
                    VC_STATE_PARAM,
                    vcStatesToQueryFor.stream()
                            .map(EvcsVCState::name)
                            .collect(Collectors.joining(",")));
        }
        return uriBuilder.build();
    }

    private void checkResponseStatusCode(HttpResponse<String> evcsHttpResponse)
            throws EvcsServiceException {
        if (200 > evcsHttpResponse.statusCode() || evcsHttpResponse.statusCode() > 299) {
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
            LOGGER.info(
                    LogHelper.buildLogMessage(
                                    ErrorResponse.RECEIVED_NON_200_RESPONSE_STATUS_CODE
                                            .getMessage())
                            .with(LOG_STATUS_CODE.getFieldName(), evcsHttpResponse.statusCode())
                            .with(LOG_MESSAGE_DESCRIPTION.getFieldName(), responseMessage));
            if (evcsHttpResponse.statusCode() != 404) {
                throw new EvcsServiceException(
                        HTTPResponse.SC_SERVER_ERROR,
                        ErrorResponse.RECEIVED_NON_200_RESPONSE_STATUS_CODE);
            }
        }
        LOGGER.info(LogHelper.buildLogMessage("Successful HTTP response from EVCS Api"));
    }

    @Tracing
    private HttpResponse<String> sendHttpRequest(HttpRequest evcsHttpRequest)
            throws EvcsServiceException {
        LOGGER.info(LogHelper.buildLogMessage("Sending HTTP request to EVCS"));
        try {
            HttpResponse<String> response =
                    httpClient.send(evcsHttpRequest, HttpResponse.BodyHandlers.ofString());
            checkResponseStatusCode(response);
            return response;
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
