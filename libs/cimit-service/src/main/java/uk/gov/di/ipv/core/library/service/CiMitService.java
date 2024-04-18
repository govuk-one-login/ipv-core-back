package uk.gov.di.ipv.core.library.service;

import com.amazonaws.services.lambda.AWSLambda;
import com.amazonaws.services.lambda.AWSLambdaClientBuilder;
import com.amazonaws.services.lambda.model.AWSLambdaException;
import com.amazonaws.services.lambda.model.InvokeRequest;
import com.amazonaws.services.lambda.model.InvokeResult;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.jwk.ECKey;
import org.apache.http.HttpStatus;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.message.StringMapMessage;
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

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Objects;

import static uk.gov.di.ipv.core.library.config.EnvironmentVariable.CIMIT_GET_CONTRAINDICATORS_LAMBDA_ARN;
import static uk.gov.di.ipv.core.library.config.EnvironmentVariable.CI_STORAGE_POST_MITIGATIONS_LAMBDA_ARN;
import static uk.gov.di.ipv.core.library.config.EnvironmentVariable.CI_STORAGE_PUT_LAMBDA_ARN;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_ERROR;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_MESSAGE_DESCRIPTION;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_PAYLOAD;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_STATUS_CODE;

public class CiMitService {
    private static final Logger LOGGER = LogManager.getLogger();
    private static final ObjectMapper objectMapper = new ObjectMapper();

    private static final String FAILED_LAMBDA_MESSAGE = "Lambda execution failed";
    private final AWSLambda lambdaClient;
    private final ConfigService configService;
    private final VerifiableCredentialValidator verifiableCredentialValidator;

    @ExcludeFromGeneratedCoverageReport
    public CiMitService(ConfigService configService) {
        this.lambdaClient = AWSLambdaClientBuilder.defaultClient();
        this.configService = configService;
        this.verifiableCredentialValidator = new VerifiableCredentialValidator(configService);
    }

    public CiMitService(
            AWSLambda lambdaClient,
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
                    objectMapper.writeValueAsString(
                            new PutCiRequest(govukSigninJourneyId, ipAddress, vc.getVcString()));

        } catch (JsonProcessingException e) {
            throw new CiPutException(e.getMessage());
        }

        InvokeRequest request =
                new InvokeRequest()
                        .withFunctionName(
                                configService.getEnvironmentVariable(CI_STORAGE_PUT_LAMBDA_ARN))
                        .withPayload(payload);

        LOGGER.info(LogHelper.buildLogMessage("Sending VC to CIMIT."));
        InvokeResult result = lambdaClient.invoke(request);

        if (lambdaExecutionFailed(result)) {
            logLambdaExecutionError(result, CI_STORAGE_PUT_LAMBDA_ARN);
            throw new CiPutException(FAILED_LAMBDA_MESSAGE);
        }
    }

    public void submitMitigatingVcList(
            List<VerifiableCredential> vcs, String govukSigninJourneyId, String ipAddress)
            throws CiPostMitigationsException {
        String payload;
        try {
            payload =
                    objectMapper.writeValueAsString(
                            new PostCiMitigationRequest(
                                    govukSigninJourneyId,
                                    ipAddress,
                                    vcs.stream().map(VerifiableCredential::getVcString).toList()));
        } catch (JsonProcessingException e) {
            throw new CiPostMitigationsException(e.getMessage());
        }
        InvokeRequest request =
                new InvokeRequest()
                        .withFunctionName(
                                configService.getEnvironmentVariable(
                                        CI_STORAGE_POST_MITIGATIONS_LAMBDA_ARN))
                        .withPayload(payload);

        LOGGER.info(LogHelper.buildLogMessage("Sending mitigating VCs to CIMIT."));
        InvokeResult result = lambdaClient.invoke(request);

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
        InvokeResult result =
                invokeClientToGetCIResult(
                        CIMIT_GET_CONTRAINDICATORS_LAMBDA_ARN,
                        govukSigninJourneyId,
                        ipAddress,
                        userId,
                        "Retrieving CIs from CIMIT system.");

        try {
            ContraIndicatorCredentialDto contraIndicatorCredential =
                    objectMapper.readValue(
                            new String(result.getPayload().array(), StandardCharsets.UTF_8),
                            ContraIndicatorCredentialDto.class);

            return extractAndValidateContraIndicatorsJwt(contraIndicatorCredential.getVc(), userId);
        } catch (JsonProcessingException e) {
            throw new CiRetrievalException(e.getMessage());
        }
    }

    private InvokeResult invokeClientToGetCIResult(
            EnvironmentVariable lambdaArnToInvoke,
            String govukSigninJourneyId,
            String ipAddress,
            String userId,
            String message)
            throws CiRetrievalException {
        LOGGER.info(LogHelper.buildLogMessage(message));

        String objectPayload;
        try {
            objectPayload =
                    objectMapper.writeValueAsString(
                            new GetCiRequest(govukSigninJourneyId, ipAddress, userId));
        } catch (JsonProcessingException e) {
            throw new CiRetrievalException(e.getMessage());
        }

        InvokeRequest request =
                new InvokeRequest()
                        .withFunctionName(configService.getEnvironmentVariable(lambdaArnToInvoke))
                        .withPayload(objectPayload);

        InvokeResult result;
        try {
            result = lambdaClient.invoke(request);
        } catch (AWSLambdaException awsLEx) {
            LOGGER.error(
                    LogHelper.buildErrorMessage("AWSLambda client invocation failed.", awsLEx));
            throw new CiRetrievalException(FAILED_LAMBDA_MESSAGE);
        }

        if (lambdaExecutionFailed(result)) {
            logLambdaExecutionError(result, lambdaArnToInvoke);
            throw new CiRetrievalException(FAILED_LAMBDA_MESSAGE);
        }
        return result;
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
        CiMitJwt ciMitJwt;
        try {
            ciMitJwt =
                    objectMapper.readValue(
                            objectMapper.writeValueAsString(claimSetJsonObject), CiMitJwt.class);
        } catch (JsonProcessingException e) {
            throw new CiRetrievalException(e.getMessage());
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

    private boolean lambdaExecutionFailed(InvokeResult result) {
        return result.getStatusCode() != HttpStatus.SC_OK || result.getFunctionError() != null;
    }

    private String getPayloadOrNull(InvokeResult result) {
        ByteBuffer payload = result.getPayload();
        return payload == null ? null : new String(payload.array(), StandardCharsets.UTF_8);
    }

    private void logLambdaExecutionError(
            InvokeResult result, EnvironmentVariable lambdaArnToInvoke) {
        HashMap<String, String> message = new HashMap<>();
        message.put(
                LOG_MESSAGE_DESCRIPTION.getFieldName(),
                "Lambda execution failed for arn:" + lambdaArnToInvoke);
        message.put(LOG_ERROR.getFieldName(), result.getFunctionError());
        message.put(LOG_STATUS_CODE.getFieldName(), String.valueOf(result.getStatusCode()));
        message.put(LOG_PAYLOAD.getFieldName(), getPayloadOrNull(result));
        message.values().removeIf(Objects::isNull);
        LOGGER.error(new StringMapMessage(message));
    }
}
