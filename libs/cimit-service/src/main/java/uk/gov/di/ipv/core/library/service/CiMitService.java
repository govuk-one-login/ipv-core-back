package uk.gov.di.ipv.core.library.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.jwk.ECKey;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.message.StringMapMessage;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.http.urlconnection.UrlConnectionHttpClient;
import software.amazon.awssdk.services.lambda.LambdaClient;
import software.amazon.awssdk.services.lambda.model.InvokeRequest;
import software.amazon.awssdk.services.lambda.model.InvokeResponse;
import software.amazon.awssdk.services.lambda.model.LambdaException;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.cimit.domain.GetCiRequest;
import uk.gov.di.ipv.core.library.cimit.domain.PostCiMitigationRequest;
import uk.gov.di.ipv.core.library.cimit.domain.PutCiRequest;
import uk.gov.di.ipv.core.library.cimit.dto.ContraIndicatorCredentialDto;
import uk.gov.di.ipv.core.library.cimit.exception.CiPostMitigationsException;
import uk.gov.di.ipv.core.library.cimit.exception.CiPutException;
import uk.gov.di.ipv.core.library.cimit.exception.CiRetrievalException;
import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
import uk.gov.di.ipv.core.library.config.EnvironmentVariable;
import uk.gov.di.ipv.core.library.domain.ContraIndicators;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants;
import uk.gov.di.ipv.core.library.domain.cimitvc.CiMitJwt;
import uk.gov.di.ipv.core.library.domain.cimitvc.CiMitVc;
import uk.gov.di.ipv.core.library.domain.cimitvc.EvidenceItem;
import uk.gov.di.ipv.core.library.exceptions.VerifiableCredentialException;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.verifiablecredential.validator.VerifiableCredentialValidator;

import java.text.ParseException;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Objects;

import static com.nimbusds.oauth2.sdk.http.HTTPResponse.SC_OK;
import static software.amazon.awssdk.regions.Region.EU_WEST_2;
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
    private final LambdaClient lambdaClient;
    private final ConfigService configService;
    private final VerifiableCredentialValidator verifiableCredentialValidator;

    @ExcludeFromGeneratedCoverageReport
    public CiMitService(ConfigService configService) {
        this.lambdaClient =
                LambdaClient.builder()
                        .region(EU_WEST_2)
                        .httpClientBuilder(UrlConnectionHttpClient.builder())
                        .build();
        this.configService = configService;
        this.verifiableCredentialValidator = new VerifiableCredentialValidator(configService);
    }

    public CiMitService(
            LambdaClient lambdaClient,
            ConfigService configService,
            VerifiableCredentialValidator verifiableCredentialValidator) {
        this.lambdaClient = lambdaClient;
        this.configService = configService;
        this.verifiableCredentialValidator = verifiableCredentialValidator;
    }

    public void submitVC(VerifiableCredential vc, String govukSigninJourneyId, String ipAddress)
            throws CiPutException {

        String payload;
        try {
            payload =
                    OBJECT_MAPPER.writeValueAsString(
                            new PutCiRequest(govukSigninJourneyId, ipAddress, vc.getVcString()));

        } catch (JsonProcessingException e) {
            throw new CiPutException("Failed to serialize PutCiRequest");
        }

        var invokeRequest =
                InvokeRequest.builder()
                        .functionName(
                                configService.getEnvironmentVariable(CI_STORAGE_PUT_LAMBDA_ARN))
                        .payload(SdkBytes.fromUtf8String(payload))
                        .build();

        LOGGER.info(LogHelper.buildLogMessage("Sending VC to CIMIT."));
        var response = lambdaClient.invoke(invokeRequest);

        if (lambdaExecutionFailed(response)) {
            logLambdaExecutionError(response, CI_STORAGE_PUT_LAMBDA_ARN);
            throw new CiPutException(FAILED_LAMBDA_MESSAGE);
        }
    }

    public void submitMitigatingVcList(
            List<VerifiableCredential> vcs, String govukSigninJourneyId, String ipAddress)
            throws CiPostMitigationsException {

        String payload;
        try {
            payload =
                    OBJECT_MAPPER.writeValueAsString(
                            new PostCiMitigationRequest(
                                    govukSigninJourneyId,
                                    ipAddress,
                                    vcs.stream().map(VerifiableCredential::getVcString).toList()));
        } catch (JsonProcessingException e) {
            throw new CiPostMitigationsException("Failed to serialize PostCiMitigationRequest");
        }

        var invokeRequest =
                InvokeRequest.builder()
                        .functionName(
                                configService.getEnvironmentVariable(
                                        CI_STORAGE_POST_MITIGATIONS_LAMBDA_ARN))
                        .payload(SdkBytes.fromUtf8String(payload))
                        .build();

        LOGGER.info(LogHelper.buildLogMessage("Sending mitigating VCs to CIMIT."));
        var result = lambdaClient.invoke(invokeRequest);

        if (lambdaExecutionFailed(result)) {
            logLambdaExecutionError(result, CI_STORAGE_POST_MITIGATIONS_LAMBDA_ARN);
            throw new CiPostMitigationsException(FAILED_LAMBDA_MESSAGE);
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

    public VerifiableCredential getContraIndicatorsVc(
            String userId, String govukSigninJourneyId, String ipAddress)
            throws CiRetrievalException {
        var response = invokeClientToGetCIResult(govukSigninJourneyId, ipAddress, userId);

        try {
            ContraIndicatorCredentialDto contraIndicatorCredential =
                    OBJECT_MAPPER.readValue(
                            response.payload().asUtf8String(), ContraIndicatorCredentialDto.class);
            return extractAndValidateContraIndicatorsJwt(contraIndicatorCredential.getVc(), userId);
        } catch (JsonProcessingException e) {
            throw new CiRetrievalException("Failed to deserialize ContraIndicatorCredentialDto");
        }
    }

    private InvokeResponse invokeClientToGetCIResult(
            String govukSigninJourneyId, String ipAddress, String userId)
            throws CiRetrievalException {
        LOGGER.info(LogHelper.buildLogMessage("Retrieving CIs from CIMIT system"));

        String payload;
        try {
            payload =
                    OBJECT_MAPPER.writeValueAsString(
                            new GetCiRequest(govukSigninJourneyId, ipAddress, userId));
        } catch (JsonProcessingException e) {
            throw new CiRetrievalException("Failed to serialize GetCiRequest");
        }

        var invokeRequest =
                InvokeRequest.builder()
                        .functionName(
                                configService.getEnvironmentVariable(
                                        CIMIT_GET_CONTRAINDICATORS_LAMBDA_ARN))
                        .payload(SdkBytes.fromUtf8String(payload))
                        .build();

        InvokeResponse response;
        try {
            response = lambdaClient.invoke(invokeRequest);
        } catch (LambdaException e) {
            LOGGER.error(LogHelper.buildErrorMessage("AWSLambda client invocation failed.", e));
            throw new CiRetrievalException(FAILED_LAMBDA_MESSAGE);
        }

        if (lambdaExecutionFailed(response)) {
            logLambdaExecutionError(response, CIMIT_GET_CONTRAINDICATORS_LAMBDA_ARN);
            throw new CiRetrievalException(FAILED_LAMBDA_MESSAGE);
        }
        return response;
    }

    private VerifiableCredential extractAndValidateContraIndicatorsJwt(
            String contraIndicatorsVC, String userId) throws CiRetrievalException {
        final String cimitComponentId =
                configService.getSsmParameter(ConfigurationVariable.CIMIT_COMPONENT_ID);
        final String cimitSigningKey =
                configService.getSsmParameter(ConfigurationVariable.CIMIT_SIGNING_KEY);
        try {
            LOGGER.info(
                    LogHelper.buildLogMessage(
                            "Validating ContraIndicators Verifiable Credential."));
            return verifiableCredentialValidator.parseAndValidate(
                    userId,
                    null,
                    contraIndicatorsVC,
                    VerifiableCredentialConstants.SECURITY_CHECK_CREDENTIAL_TYPE,
                    ECKey.parse(cimitSigningKey),
                    cimitComponentId,
                    false);
        } catch (ParseException e) {
            LOGGER.error(LogHelper.buildErrorMessage("Error parsing CIMIT signing key", e));
            throw new CiRetrievalException(
                    ErrorResponse.FAILED_TO_PARSE_CIMIT_SIGNING_KEY.getMessage());
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
}
