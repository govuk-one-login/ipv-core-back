package uk.gov.di.ipv.core.library.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.entity.ContentType;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.message.StringMapMessage;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.http.urlconnection.UrlConnectionHttpClient;
import software.amazon.awssdk.services.lambda.LambdaClient;
import software.amazon.awssdk.services.lambda.model.InvokeRequest;
import software.amazon.awssdk.services.lambda.model.InvokeResponse;
import software.amazon.awssdk.services.lambda.model.LambdaException;
import software.amazon.lambda.powertools.tracing.Tracing;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.cimit.domain.GetCiRequest;
import uk.gov.di.ipv.core.library.cimit.domain.PostCiMitigationRequest;
import uk.gov.di.ipv.core.library.cimit.domain.PostCiPrivateApiRequest;
import uk.gov.di.ipv.core.library.cimit.domain.PostMitigationsPrivateApiRequest;
import uk.gov.di.ipv.core.library.cimit.domain.PrivateApiResponse;
import uk.gov.di.ipv.core.library.cimit.domain.PutCiRequest;
import uk.gov.di.ipv.core.library.cimit.dto.ContraIndicatorCredentialDto;
import uk.gov.di.ipv.core.library.cimit.exception.CiPostMitigationsException;
import uk.gov.di.ipv.core.library.cimit.exception.CiPutException;
import uk.gov.di.ipv.core.library.cimit.exception.CiRetrievalException;
import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
import uk.gov.di.ipv.core.library.config.EnvironmentVariable;
import uk.gov.di.ipv.core.library.domain.ContraIndicators;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.domain.cimitvc.CiMitJwt;
import uk.gov.di.ipv.core.library.domain.cimitvc.CiMitVc;
import uk.gov.di.ipv.core.library.domain.cimitvc.EvidenceItem;
import uk.gov.di.ipv.core.library.exceptions.NonRetryableException;
import uk.gov.di.ipv.core.library.exceptions.VerifiableCredentialException;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.verifiablecredential.validator.VerifiableCredentialValidator;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Objects;

import static com.nimbusds.oauth2.sdk.http.HTTPResponse.SC_OK;
import static org.apache.http.HttpHeaders.CONTENT_TYPE;
import static software.amazon.awssdk.regions.Region.EU_WEST_2;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.CIMIT_INTERNAL_API_KEY;
import static uk.gov.di.ipv.core.library.config.CoreFeatureFlag.CIMIT_API_GATEWAY_ENABLED;
import static uk.gov.di.ipv.core.library.config.EnvironmentVariable.CIMIT_GET_CONTRAINDICATORS_LAMBDA_ARN;
import static uk.gov.di.ipv.core.library.config.EnvironmentVariable.CI_STORAGE_POST_MITIGATIONS_LAMBDA_ARN;
import static uk.gov.di.ipv.core.library.config.EnvironmentVariable.CI_STORAGE_PUT_LAMBDA_ARN;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_ERROR;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_MESSAGE_DESCRIPTION;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_PAYLOAD;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_STATUS_CODE;

public class CiMitService {
    private static final Logger LOGGER = LogManager.getLogger();
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    private static final String FAILED_LAMBDA_MESSAGE = "Lambda execution failed";
    private static final String FAILED_API_REQUEST = "API request failed";

    public static final String GOVUK_SIGNIN_JOURNEY_ID_HEADER = "govuk-signin-journey-id";
    public static final String IP_ADDRESS_HEADER = "ip-address";
    private static final String USER_ID_PARAMETER = "user_id";
    public static final String X_API_KEY_HEADER = "x-api-key";

    private static final String POST_CI_ENDPOINT = "/contra-indicators/detect";
    private static final String POST_MITIGATIONS_ENDPOINT = "/contra-indicators/mitigate";
    private static final String GET_VCS_ENDPOINT = "/contra-indicators";

    public static final String FAILED_RESPONSE = "fail";

    private final LambdaClient lambdaClient;
    private static final String LIVE_ALIAS = "live";
    private final ConfigService configService;
    private final VerifiableCredentialValidator verifiableCredentialValidator;
    private final HttpClient httpClient;

    @ExcludeFromGeneratedCoverageReport
    public CiMitService(ConfigService configService) {
        this.lambdaClient =
                LambdaClient.builder()
                        .region(EU_WEST_2)
                        .httpClientBuilder(UrlConnectionHttpClient.builder())
                        .build();
        this.configService = configService;
        this.verifiableCredentialValidator = new VerifiableCredentialValidator(configService);
        this.httpClient = HttpClient.newHttpClient();
    }

    public CiMitService(
            LambdaClient lambdaClient,
            ConfigService configService,
            VerifiableCredentialValidator verifiableCredentialValidator) {
        this.lambdaClient = lambdaClient;
        this.configService = configService;
        this.verifiableCredentialValidator = verifiableCredentialValidator;
        this.httpClient = HttpClient.newHttpClient();
    }

    @ExcludeFromGeneratedCoverageReport
    public CiMitService(
            LambdaClient lambdaClient,
            ConfigService configService,
            VerifiableCredentialValidator verifiableCredentialValidator,
            HttpClient httpClient) {
        this.lambdaClient = lambdaClient;
        this.configService = configService;
        this.verifiableCredentialValidator = verifiableCredentialValidator;
        this.httpClient = httpClient;
    }

    @Tracing
    public void submitVC(VerifiableCredential vc, String govukSigninJourneyId, String ipAddress)
            throws CiPutException {

        LOGGER.info(LogHelper.buildLogMessage("Sending VC to CIMIT."));
        try {
            if (configService.enabled(CIMIT_API_GATEWAY_ENABLED)) {
                var payload =
                        OBJECT_MAPPER.writeValueAsString(
                                new PostCiPrivateApiRequest(vc.getVcString()));

                var uri = getUriBuilderWithBaseApiUrl(POST_CI_ENDPOINT).build();

                var response = sendPostHttpRequest(uri, govukSigninJourneyId, ipAddress, payload);
                var parsedResponse =
                        OBJECT_MAPPER.readValue(response.body(), PrivateApiResponse.class);

                if (FAILED_RESPONSE.equals(parsedResponse.result())) {
                    logApiRequestError(parsedResponse);
                    throw new CiPutException(FAILED_API_REQUEST);
                }

            } else {
                var payload =
                        OBJECT_MAPPER.writeValueAsString(
                                new PutCiRequest(
                                        govukSigninJourneyId, ipAddress, vc.getVcString()));

                var invokeRequest =
                        InvokeRequest.builder()
                                .functionName(
                                        configService.getEnvironmentVariable(
                                                CI_STORAGE_PUT_LAMBDA_ARN))
                                .payload(SdkBytes.fromUtf8String(payload))
                                .qualifier(LIVE_ALIAS)
                                .build();

                var response = lambdaClient.invoke(invokeRequest);

                if (lambdaExecutionFailed(response)) {
                    logLambdaExecutionError(response, CI_STORAGE_PUT_LAMBDA_ARN);
                    throw new CiPutException(FAILED_LAMBDA_MESSAGE);
                }
            }
        } catch (JsonProcessingException e) {
            throw new CiPutException("Failed to serialize payload for post CI request.");
        } catch (CiPutException e) {
            throw e;
        } catch (Exception e) {
            throw new CiPutException(FAILED_LAMBDA_MESSAGE);
        }
    }

    @Tracing
    public void submitMitigatingVcList(
            List<VerifiableCredential> vcs, String govukSigninJourneyId, String ipAddress)
            throws CiPostMitigationsException {

        LOGGER.info(LogHelper.buildLogMessage("Sending mitigating VCs to CIMIT."));
        try {
            if (configService.enabled(CIMIT_API_GATEWAY_ENABLED)) {
                var payload =
                        OBJECT_MAPPER.writeValueAsString(
                                new PostMitigationsPrivateApiRequest(
                                        vcs.stream()
                                                .map(VerifiableCredential::getVcString)
                                                .toList()));

                var uri = getUriBuilderWithBaseApiUrl(POST_MITIGATIONS_ENDPOINT).build();

                var response = sendPostHttpRequest(uri, govukSigninJourneyId, ipAddress, payload);
                var parsedResponse =
                        OBJECT_MAPPER.readValue(response.body(), PrivateApiResponse.class);

                if (FAILED_RESPONSE.equals(parsedResponse.result())) {
                    logApiRequestError(parsedResponse);
                    throw new CiPostMitigationsException(FAILED_API_REQUEST);
                }

            } else {
                String payload =
                        OBJECT_MAPPER.writeValueAsString(
                                new PostCiMitigationRequest(
                                        govukSigninJourneyId,
                                        ipAddress,
                                        vcs.stream()
                                                .map(VerifiableCredential::getVcString)
                                                .toList()));

                var invokeRequest =
                        InvokeRequest.builder()
                                .functionName(
                                        configService.getEnvironmentVariable(
                                                CI_STORAGE_POST_MITIGATIONS_LAMBDA_ARN))
                                .payload(SdkBytes.fromUtf8String(payload))
                                .qualifier(LIVE_ALIAS)
                                .build();

                var result = lambdaClient.invoke(invokeRequest);

                if (lambdaExecutionFailed(result)) {
                    logLambdaExecutionError(result, CI_STORAGE_POST_MITIGATIONS_LAMBDA_ARN);
                    throw new CiPostMitigationsException(FAILED_LAMBDA_MESSAGE);
                }
            }
        } catch (JsonProcessingException e) {
            throw new CiPostMitigationsException(
                    "Failed to serialize payload for post mitigations request");
        } catch (CiPostMitigationsException e) {
            throw e;
        } catch (Exception e) {
            throw new CiPostMitigationsException("Failed to submit mitigating VCs list.");
        }
    }

    @Tracing
    public ContraIndicators getContraIndicators(
            String userId, String govukSigninJourneyId, String ipAddress)
            throws CiRetrievalException {
        var vc = getContraIndicatorsVc(userId, govukSigninJourneyId, ipAddress);

        return getContraIndicators(vc);
    }

    @Tracing
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
        var response = invokeClientToGetCIResult(govukSigninJourneyId, ipAddress, userId);

        try {
            ContraIndicatorCredentialDto contraIndicatorCredential =
                    OBJECT_MAPPER.readValue(response, ContraIndicatorCredentialDto.class);
            return extractAndValidateContraIndicatorsJwt(contraIndicatorCredential.getVc(), userId);
        } catch (JsonProcessingException e) {
            throw new CiRetrievalException("Failed to deserialize ContraIndicatorCredentialDto");
        }
    }

    private String invokeClientToGetCIResult(
            String govukSigninJourneyId, String ipAddress, String userId)
            throws CiRetrievalException {
        LOGGER.info(LogHelper.buildLogMessage("Retrieving CIs from CIMIT system"));
        try {
            if (configService.enabled(CIMIT_API_GATEWAY_ENABLED)) {
                var uriBuilder = getUriBuilderWithBaseApiUrl(GET_VCS_ENDPOINT);

                var uri = uriBuilder.addParameter(USER_ID_PARAMETER, userId).build();

                var response = sendGetHttpRequest(uri, govukSigninJourneyId, ipAddress);

                if (response.statusCode() != SC_OK) {
                    var parsedResponse =
                            OBJECT_MAPPER.readValue(response.body(), PrivateApiResponse.class);
                    logApiRequestError(parsedResponse);
                    throw new CiRetrievalException(FAILED_API_REQUEST);
                }
                return response.body();
            } else {
                var payload = getPayloadForGetCiRequest(govukSigninJourneyId, ipAddress, userId);

                var invokeRequest =
                        InvokeRequest.builder()
                                .functionName(
                                        configService.getEnvironmentVariable(
                                                CIMIT_GET_CONTRAINDICATORS_LAMBDA_ARN))
                                .payload(SdkBytes.fromUtf8String(payload))
                                .qualifier(LIVE_ALIAS)
                                .build();

                InvokeResponse response = lambdaClient.invoke(invokeRequest);

                if (lambdaExecutionFailed(response)) {
                    logLambdaExecutionError(response, CIMIT_GET_CONTRAINDICATORS_LAMBDA_ARN);
                    throw new CiRetrievalException(FAILED_LAMBDA_MESSAGE);
                }
                return response.payload().asUtf8String();
            }
        } catch (LambdaException e) {
            LOGGER.error(LogHelper.buildErrorMessage("AWSLambda client invocation failed.", e));
            throw new CiRetrievalException(FAILED_LAMBDA_MESSAGE);
        } catch (CiRetrievalException e) {
            throw e;
        } catch (Exception e) {
            throw new CiRetrievalException("Failed to get CI from CIMIT");
        }
    }

    private String getPayloadForGetCiRequest(
            String govukSigninJourneyId, String ipAddress, String userId)
            throws CiRetrievalException {
        try {
            return OBJECT_MAPPER.writeValueAsString(
                    new GetCiRequest(govukSigninJourneyId, ipAddress, userId));
        } catch (JsonProcessingException e) {
            throw new CiRetrievalException("Failed to serialize GetCiRequest");
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
        CiMitJwt ciMitJwt = OBJECT_MAPPER.convertValue(claimSetJsonObject, CiMitJwt.class);
        if (ciMitJwt == null) {
            String message = "Failed to convert claim set object to CiMitJwt";
            LOGGER.error(LogHelper.buildLogMessage(message));
            throw new CiRetrievalException(message);
        }
        CiMitVc vcClaim = ciMitJwt.getVc();
        if (vcClaim == null) {
            String message = "VC claim not found in CiMit JWT";
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

    private boolean lambdaExecutionFailed(InvokeResponse response) {
        return response.statusCode() != SC_OK || response.functionError() != null;
    }

    private String getPayloadOrNull(InvokeResponse response) {
        var payload = response.payload();
        return payload == null ? null : payload.asUtf8String();
    }

    private void logLambdaExecutionError(
            InvokeResponse response, EnvironmentVariable lambdaArnToInvoke) {
        HashMap<String, String> message = new HashMap<>();
        message.put(
                LOG_MESSAGE_DESCRIPTION.getFieldName(),
                "Lambda execution failed for arn:" + lambdaArnToInvoke);
        message.put(LOG_ERROR.getFieldName(), response.functionError());
        message.put(LOG_STATUS_CODE.getFieldName(), String.valueOf(response.statusCode()));
        message.put(LOG_PAYLOAD.getFieldName(), getPayloadOrNull(response));
        message.values().removeIf(Objects::isNull);
        LOGGER.error(new StringMapMessage(message));
    }

    private void logApiRequestError(PrivateApiResponse failedResponse) {
        LOGGER.error(LogHelper.buildErrorMessage(FAILED_API_REQUEST, failedResponse.reason()));
    }

    private HttpResponse<String> sendPostHttpRequest(
            URI uri, String govukSigninJourneyId, String ipAddress, String payload)
            throws NonRetryableException {
        var httpRequestBuilder = buildHttpRequest(uri, govukSigninJourneyId, ipAddress);
        httpRequestBuilder.POST(HttpRequest.BodyPublishers.ofString(payload));

        return sendHttpRequest(httpRequestBuilder.build());
    }

    private HttpResponse<String> sendGetHttpRequest(
            URI uri, String govukSigninJourneyId, String ipAddress) throws NonRetryableException {
        var httpRequestBuilder = buildHttpRequest(uri, govukSigninJourneyId, ipAddress).GET();

        return sendHttpRequest(httpRequestBuilder.build());
    }

    private HttpRequest.Builder buildHttpRequest(
            URI uri, String govukSigninJourneyId, String ipAddress) {
        var requestBuilder =
                HttpRequest.newBuilder()
                        .uri(uri)
                        .header(GOVUK_SIGNIN_JOURNEY_ID_HEADER, govukSigninJourneyId)
                        .header(CONTENT_TYPE, ContentType.APPLICATION_JSON.toString())
                        .header(
                                X_API_KEY_HEADER,
                                configService.getApiKeySecret(CIMIT_INTERNAL_API_KEY));

        if (ipAddress != null) {
            requestBuilder.header(IP_ADDRESS_HEADER, ipAddress);
        }
        return requestBuilder;
    }

    private HttpResponse<String> sendHttpRequest(HttpRequest cimitHttpRequest)
            throws NonRetryableException {
        try {
            LOGGER.info(LogHelper.buildLogMessage("Sending HTTP request to CiMit."));
            return httpClient.send(cimitHttpRequest, HttpResponse.BodyHandlers.ofString());
        } catch (IOException e) {
            throw new NonRetryableException(e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new NonRetryableException(e);
        }
    }

    private URIBuilder getUriBuilderWithBaseApiUrl(String endpointUrl) throws URISyntaxException {
        var baseUri =
                configService.getParameter(ConfigurationVariable.CIMIT_INTERNAL_API_BASE_URL)
                        + endpointUrl;

        return new URIBuilder(baseUri);
    }
}
