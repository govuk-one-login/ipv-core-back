package uk.gov.di.ipv.core.library.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.entity.ContentType;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import software.amazon.lambda.powertools.tracing.Tracing;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.cimit.domain.CimitApiResponse;
import uk.gov.di.ipv.core.library.cimit.domain.PostCiApiRequest;
import uk.gov.di.ipv.core.library.cimit.domain.PostMitigationsApiRequest;
import uk.gov.di.ipv.core.library.cimit.dto.ContraIndicatorCredentialDto;
import uk.gov.di.ipv.core.library.cimit.exception.CiPostMitigationsException;
import uk.gov.di.ipv.core.library.cimit.exception.CiPutException;
import uk.gov.di.ipv.core.library.cimit.exception.CiRetrievalException;
import uk.gov.di.ipv.core.library.cimit.exception.CimitHttpRequestException;
import uk.gov.di.ipv.core.library.cimit.exception.PostApiException;
import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
import uk.gov.di.ipv.core.library.domain.ContraIndicators;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.domain.cimitvc.CimitJwt;
import uk.gov.di.ipv.core.library.domain.cimitvc.CimitVc;
import uk.gov.di.ipv.core.library.domain.cimitvc.EvidenceItem;
import uk.gov.di.ipv.core.library.exceptions.VerifiableCredentialException;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.tracing.TracingHttpClient;
import uk.gov.di.ipv.core.library.verifiablecredential.validator.VerifiableCredentialValidator;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Collections;
import java.util.List;

import static com.nimbusds.oauth2.sdk.http.HTTPResponse.SC_OK;
import static org.apache.http.HttpHeaders.CONTENT_TYPE;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.CIMIT_API_KEY;

public class CimitService {
    private static final Logger LOGGER = LogManager.getLogger();
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    public static final String FAILED_API_REQUEST = "API request failed";

    public static final String GOVUK_SIGNIN_JOURNEY_ID_HEADER = "govuk-signin-journey-id";
    public static final String IP_ADDRESS_HEADER = "ip-address";
    private static final String USER_ID_PARAMETER = "user_id";
    public static final String X_API_KEY_HEADER = "x-api-key";

    public static final String POST_CI_ENDPOINT = "/contra-indicators/detect";
    public static final String POST_MITIGATIONS_ENDPOINT = "/contra-indicators/mitigate";
    public static final String GET_VCS_ENDPOINT = "/contra-indicators";
    private static final String NOT_REQUIRED = "notRequired";

    public static final String FAILED_RESPONSE = "fail";

    private final ConfigService configService;
    private final VerifiableCredentialValidator verifiableCredentialValidator;
    private final HttpClient httpClient;

    @ExcludeFromGeneratedCoverageReport
    public CimitService(ConfigService configService) {
        this.configService = configService;
        this.verifiableCredentialValidator = new VerifiableCredentialValidator(configService);
        this.httpClient = TracingHttpClient.newHttpClient();
    }

    @ExcludeFromGeneratedCoverageReport
    public CimitService(
            ConfigService configService,
            VerifiableCredentialValidator verifiableCredentialValidator,
            HttpClient httpClient) {
        this.configService = configService;
        this.verifiableCredentialValidator = verifiableCredentialValidator;
        this.httpClient = httpClient;
    }

    @Tracing
    public void submitVC(VerifiableCredential vc, String govukSigninJourneyId, String ipAddress)
            throws CiPutException {

        LOGGER.info(LogHelper.buildLogMessage("Sending VC to CIMIT."));
        try {
            var payload = OBJECT_MAPPER.writeValueAsString(new PostCiApiRequest(vc.getVcString()));

            sendPostHttpRequest(POST_CI_ENDPOINT, govukSigninJourneyId, ipAddress, payload);
        } catch (JsonProcessingException e) {
            throw new CiPutException("Failed to serialize payload for post CI request.");
        } catch (PostApiException | CimitHttpRequestException | URISyntaxException e) {
            throw new CiPutException(FAILED_API_REQUEST);
        }
    }

    @Tracing
    public void submitMitigatingVcList(
            List<VerifiableCredential> vcs, String govukSigninJourneyId, String ipAddress)
            throws CiPostMitigationsException {

        LOGGER.info(LogHelper.buildLogMessage("Sending mitigating VCs to CIMIT."));
        try {
            var payload =
                    OBJECT_MAPPER.writeValueAsString(
                            new PostMitigationsApiRequest(
                                    vcs.stream().map(VerifiableCredential::getVcString).toList()));

            sendPostHttpRequest(
                    POST_MITIGATIONS_ENDPOINT, govukSigninJourneyId, ipAddress, payload);

        } catch (JsonProcessingException e) {
            throw new CiPostMitigationsException(
                    "Failed to serialize payload for post mitigations request");
        } catch (PostApiException | CimitHttpRequestException | URISyntaxException e) {
            throw new CiPostMitigationsException(FAILED_API_REQUEST);
        }
    }

    public ContraIndicators getContraIndicators(
            String userId, String govukSigninJourneyId, String ipAddress)
            throws CiRetrievalException {
        var vc = getContraIndicatorsVc(userId, govukSigninJourneyId, ipAddress);

        return getContraIndicators(vc);
    }

    public ContraIndicators getContraIndicators(VerifiableCredential vc)
            throws CiRetrievalException {
        var evidenceItem = parseContraIndicatorEvidence(vc);
        return ContraIndicators.builder()
                .usersContraIndicators(
                        evidenceItem.getContraIndicator() != null
                                ? evidenceItem.getContraIndicator()
                                : Collections.emptyList())
                .build();
    }

    @Tracing
    public VerifiableCredential getContraIndicatorsVc(
            String userId, String govukSigninJourneyId, String ipAddress)
            throws CiRetrievalException {
        var response = sendGetHttpRequest(govukSigninJourneyId, ipAddress, userId);

        try {
            ContraIndicatorCredentialDto contraIndicatorCredential =
                    OBJECT_MAPPER.readValue(response, ContraIndicatorCredentialDto.class);
            return extractAndValidateContraIndicatorsJwt(contraIndicatorCredential.getVc(), userId);
        } catch (JsonProcessingException e) {
            throw new CiRetrievalException("Failed to deserialize ContraIndicatorCredentialDto");
        }
    }

    private String sendGetHttpRequest(String govukSigninJourneyId, String ipAddress, String userId)
            throws CiRetrievalException {
        LOGGER.info(LogHelper.buildLogMessage("Retrieving CIs from CIMIT system"));
        try {
            var response =
                    sendHttpRequest(
                            buildHttpRequest(
                                            getUriBuilderWithBaseApiUrl(GET_VCS_ENDPOINT)
                                                    .addParameter(USER_ID_PARAMETER, userId)
                                                    .build(),
                                            govukSigninJourneyId,
                                            ipAddress)
                                    .GET()
                                    .build());

            if (response.statusCode() != SC_OK) {
                logApiRequestError(
                        OBJECT_MAPPER.readValue(response.body(), CimitApiResponse.class));
                throw new CiRetrievalException(FAILED_API_REQUEST);
            }
            return response.body();
        } catch (CimitHttpRequestException | URISyntaxException | JsonProcessingException e) {
            throw new CiRetrievalException(FAILED_API_REQUEST);
        }
    }

    private VerifiableCredential extractAndValidateContraIndicatorsJwt(
            String contraIndicatorsVC, String userId) throws CiRetrievalException {
        final String cimitComponentId =
                configService.getParameter(ConfigurationVariable.CIMIT_COMPONENT_ID);
        final String cimitSigningKey =
                configService.getParameter(ConfigurationVariable.CIMIT_SIGNING_KEY);
        try {
            LOGGER.info(
                    LogHelper.buildLogMessage(
                            "Validating ContraIndicators Verifiable Credential."));
            return verifiableCredentialValidator.parseAndValidate(
                    userId, null, contraIndicatorsVC, cimitSigningKey, cimitComponentId, false);
        } catch (VerifiableCredentialException vcEx) {
            LOGGER.error(LogHelper.buildLogMessage(vcEx.getErrorResponse().getMessage()));
            throw new CiRetrievalException(vcEx.getErrorResponse().getMessage());
        }
    }

    private EvidenceItem parseContraIndicatorEvidence(VerifiableCredential vc)
            throws CiRetrievalException {

        var claimSetJsonObject = vc.getClaimsSet().toJSONObject();
        CimitJwt cimitJwt = OBJECT_MAPPER.convertValue(claimSetJsonObject, CimitJwt.class);
        if (cimitJwt == null) {
            String message = "Failed to convert claim set object to CIMIT JWT";
            LOGGER.error(LogHelper.buildLogMessage(message));
            throw new CiRetrievalException(message);
        }
        CimitVc vcClaim = cimitJwt.getVc();
        if (vcClaim == null) {
            String message = "VC claim not found in CIMIT JWT";
            LOGGER.error(LogHelper.buildLogMessage(message));
            throw new CiRetrievalException(message);
        }

        List<EvidenceItem> evidenceList = vcClaim.getEvidence();
        if (evidenceList == null || evidenceList.size() != 1) {
            String message = "Unexpected evidence count";
            LOGGER.error(
                    LogHelper.buildErrorMessage(
                            message,
                            String.format(
                                    "Expected one evidence item, got %d",
                                    evidenceList == null ? 0 : evidenceList.size())));
            throw new CiRetrievalException(message);
        }

        return evidenceList.get(0);
    }

    private void logApiRequestError(CimitApiResponse failedResponse) {
        LOGGER.error(LogHelper.buildErrorMessage(FAILED_API_REQUEST, failedResponse.reason()));
    }

    private void sendPostHttpRequest(
            String endpoint, String govukSigninJourneyId, String ipAddress, String payload)
            throws PostApiException, URISyntaxException, CimitHttpRequestException,
                    JsonProcessingException {
        var uri = getUriBuilderWithBaseApiUrl(endpoint).build();

        var httpRequestBuilder = buildHttpRequest(uri, govukSigninJourneyId, ipAddress);
        httpRequestBuilder.POST(HttpRequest.BodyPublishers.ofString(payload));

        var response = sendHttpRequest(httpRequestBuilder.build());

        var parsedResponse = OBJECT_MAPPER.readValue(response.body(), CimitApiResponse.class);

        if (FAILED_RESPONSE.equals(parsedResponse.result())) {
            logApiRequestError(parsedResponse);
            throw new PostApiException(FAILED_API_REQUEST);
        }
    }

    private HttpRequest.Builder buildHttpRequest(
            URI uri, String govukSigninJourneyId, String ipAddress) {
        var requestBuilder =
                HttpRequest.newBuilder()
                        .uri(uri)
                        .header(CONTENT_TYPE, ContentType.APPLICATION_JSON.toString());

        var apiKey = configService.getSecret(CIMIT_API_KEY);
        if (apiKey != null && !apiKey.equals(NOT_REQUIRED)) {
            requestBuilder.header(X_API_KEY_HEADER, configService.getSecret(CIMIT_API_KEY));
        }

        if (govukSigninJourneyId != null) {
            requestBuilder.header(GOVUK_SIGNIN_JOURNEY_ID_HEADER, govukSigninJourneyId);
        }

        if (ipAddress != null) {
            requestBuilder.header(IP_ADDRESS_HEADER, ipAddress);
        }
        return requestBuilder;
    }

    private HttpResponse<String> sendHttpRequest(HttpRequest cimitHttpRequest)
            throws CimitHttpRequestException {
        try {
            LOGGER.info(LogHelper.buildLogMessage("Sending HTTP request to CIMIT."));
            return httpClient.send(cimitHttpRequest, HttpResponse.BodyHandlers.ofString());
        } catch (InterruptedException e) {
            LOGGER.error(
                    LogHelper.buildErrorMessage(
                            "Client interrupted sending http request to CIMIT", e));
            Thread.currentThread().interrupt();
            throw new CimitHttpRequestException(FAILED_API_REQUEST);
        } catch (IOException e) {
            LOGGER.error(LogHelper.buildErrorMessage("Http request to CIMIT failed", e));
            throw new CimitHttpRequestException(FAILED_API_REQUEST);
        }
    }

    private URIBuilder getUriBuilderWithBaseApiUrl(String endpointUrl) throws URISyntaxException {
        var baseUri =
                configService.getParameter(ConfigurationVariable.CIMIT_API_BASE_URL) + endpointUrl;

        return new URIBuilder(baseUri);
    }
}
