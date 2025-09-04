package uk.gov.di.ipv.core.library.cimit.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.oauth2.sdk.util.StringUtils;
import org.apache.hc.core5.http.ContentType;
import org.apache.hc.core5.net.URIBuilder;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
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
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.exceptions.VerifiableCredentialException;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.tracing.TracingHttpClient;
import uk.gov.di.ipv.core.library.verifiablecredential.validator.VerifiableCredentialValidator;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.List;

import static com.nimbusds.oauth2.sdk.http.HTTPResponse.SC_OK;
import static org.apache.hc.core5.http.HttpHeaders.CONTENT_TYPE;
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

    public static final String FAILED_RESPONSE = "fail";

    private final ConfigService configService;
    private final VerifiableCredentialValidator verifiableCredentialValidator;
    private final HttpClient httpClient;

    private final IpvSessionService ipvSessionService;

    @ExcludeFromGeneratedCoverageReport
    public CimitService(ConfigService configService) {
        this.configService = configService;
        this.verifiableCredentialValidator = new VerifiableCredentialValidator(configService);
        this.httpClient = TracingHttpClient.newHttpClient();
        this.ipvSessionService = new IpvSessionService(configService);
    }

    @ExcludeFromGeneratedCoverageReport
    public CimitService(
            ConfigService configService,
            VerifiableCredentialValidator verifiableCredentialValidator,
            HttpClient httpClient,
            IpvSessionService ipvSessionService) {
        this.configService = configService;
        this.verifiableCredentialValidator = verifiableCredentialValidator;
        this.httpClient = httpClient;
        this.ipvSessionService = ipvSessionService;
    }

    public void submitVC(VerifiableCredential vc, String govukSigninJourneyId, String ipAddress)
            throws CiPutException {
        LOGGER.info(LogHelper.buildLogMessage("Sending VC to CIMIT."));
        var payload = createPostCiPayload(vc);
        try {
            sendPostHttpRequest(POST_CI_ENDPOINT, govukSigninJourneyId, ipAddress, payload);
        } catch (PostApiException | CimitHttpRequestException | URISyntaxException e) {
            LOGGER.error(LogHelper.buildErrorMessage("Error sending VC to CIMIT", e));
            throw new CiPutException(FAILED_API_REQUEST);
        }
    }

    public void submitMitigatingVcList(
            List<VerifiableCredential> vcs, String govukSigninJourneyId, String ipAddress)
            throws CiPostMitigationsException {

        LOGGER.info(LogHelper.buildLogMessage("Sending mitigating VCs to CIMIT."));
        var payload = createSubmitMitigationPayload(vcs);
        try {
            sendPostHttpRequest(
                    POST_MITIGATIONS_ENDPOINT, govukSigninJourneyId, ipAddress, payload);
        } catch (PostApiException | CimitHttpRequestException | URISyntaxException e) {
            LOGGER.error(LogHelper.buildErrorMessage("Error sending mitigation to CIMIT", e));
            throw new CiPostMitigationsException(FAILED_API_REQUEST);
        }
    }

    public VerifiableCredential fetchContraIndicatorsVc(
            String userId,
            String govukSigninJourneyId,
            String ipAddress,
            IpvSessionItem ipvSessionItem)
            throws CiRetrievalException {
        var vc = fetchContraIndicatorsVc(userId, govukSigninJourneyId, ipAddress);

        var inSessionSecurityCredential = ipvSessionItem.getSecurityCheckCredential();
        if (StringUtils.isBlank(inSessionSecurityCredential)
                || !inSessionSecurityCredential.equals(vc.getVcString())) {
            ipvSessionItem.setSecurityCheckCredential(vc.getVcString());
            ipvSessionService.updateIpvSession(ipvSessionItem);
        }

        return vc;
    }

    private VerifiableCredential fetchContraIndicatorsVc(
            String userId, String govukSigninJourneyId, String ipAddress)
            throws CiRetrievalException {
        var response = sendGetHttpRequest(govukSigninJourneyId, ipAddress, userId);

        try {
            var contraIndicatorCredential =
                    OBJECT_MAPPER.readValue(response, ContraIndicatorCredentialDto.class);
            return extractAndValidateContraIndicatorsJwt(contraIndicatorCredential.getVc(), userId);
        } catch (JsonProcessingException e) {
            LOGGER.error(LogHelper.buildErrorMessage("Error reading CIMIT VC", e));
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
                configService.getConfiguration().getCimit().getComponentId().toString();
        final String cimitSigningKey =
                configService.getConfiguration().getCimit().getSigningKey().toString();
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

    private void logApiRequestError(CimitApiResponse failedResponse) {
        LOGGER.error(
                LogHelper.buildErrorMessage(
                        FAILED_API_REQUEST,
                        failedResponse.errorMessage(),
                        failedResponse.reason()));
    }

    private void sendPostHttpRequest(
            String endpoint, String govukSigninJourneyId, String ipAddress, String payload)
            throws PostApiException, URISyntaxException, CimitHttpRequestException {
        var parsedResponse =
                parseResponse(
                        sendHttpRequest(
                                buildHttpRequest(
                                                getUriBuilderWithBaseApiUrl(endpoint).build(),
                                                govukSigninJourneyId,
                                                ipAddress)
                                        .POST(HttpRequest.BodyPublishers.ofString(payload))
                                        .build()));

        if (FAILED_RESPONSE.equals(parsedResponse.result())) {
            logApiRequestError(parsedResponse);
            throw new PostApiException(FAILED_API_REQUEST);
        }
    }

    private CimitApiResponse parseResponse(HttpResponse<String> response) throws PostApiException {
        try {
            return OBJECT_MAPPER.readValue(response.body(), CimitApiResponse.class);
        } catch (JsonProcessingException e) {
            LOGGER.error(LogHelper.buildErrorMessage("Failed to parse CIMIT response", e));
            throw new PostApiException("Failed to parse CIMIT response");
        }
    }

    private HttpRequest.Builder buildHttpRequest(
            URI uri, String govukSigninJourneyId, String ipAddress) {
        var requestBuilder =
                HttpRequest.newBuilder()
                        .uri(uri)
                        .header(CONTENT_TYPE, ContentType.APPLICATION_JSON.toString());

        var apiKey = configService.getSecret(CIMIT_API_KEY);

        if (StringUtils.isNotBlank(apiKey)) {
            requestBuilder.header(X_API_KEY_HEADER, configService.getSecret(CIMIT_API_KEY));
        }

        if (StringUtils.isNotBlank(govukSigninJourneyId)) {
            requestBuilder.header(GOVUK_SIGNIN_JOURNEY_ID_HEADER, govukSigninJourneyId);
        }

        if (StringUtils.isNotBlank(ipAddress)) {
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
                configService.getConfiguration().getCimit().getApiBaseUrl().toString()
                        + endpointUrl;

        return new URIBuilder(baseUri);
    }

    private String createPostCiPayload(VerifiableCredential vc) throws CiPutException {
        try {
            return OBJECT_MAPPER.writeValueAsString(new PostCiApiRequest(vc.getVcString()));
        } catch (JsonProcessingException e) {
            LOGGER.error(LogHelper.buildErrorMessage("Error creating VC submission payload", e));
            throw new CiPutException("Failed to serialize VC submission payload");
        }
    }

    private String createSubmitMitigationPayload(List<VerifiableCredential> vcs)
            throws CiPostMitigationsException {
        try {
            return OBJECT_MAPPER.writeValueAsString(
                    new PostMitigationsApiRequest(
                            vcs.stream().map(VerifiableCredential::getVcString).toList()));
        } catch (JsonProcessingException e) {
            LOGGER.error(
                    LogHelper.buildErrorMessage("Error creating mitigation submission payload", e));
            throw new CiPostMitigationsException(
                    "Failed to serialize mitigation submission payload");
        }
    }
}
