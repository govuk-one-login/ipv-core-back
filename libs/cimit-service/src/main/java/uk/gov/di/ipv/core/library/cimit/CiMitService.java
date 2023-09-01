package uk.gov.di.ipv.core.library.cimit;

import com.amazonaws.services.lambda.AWSLambda;
import com.amazonaws.services.lambda.AWSLambdaClientBuilder;
import com.amazonaws.services.lambda.model.AWSLambdaException;
import com.amazonaws.services.lambda.model.InvokeRequest;
import com.amazonaws.services.lambda.model.InvokeResult;
import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.SignedJWT;
import org.apache.http.HttpStatus;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.message.StringMapMessage;
import uk.gov.di.ipv.core.library.cimit.domain.GetCiRequest;
import uk.gov.di.ipv.core.library.cimit.domain.GetCiResponse;
import uk.gov.di.ipv.core.library.cimit.domain.PostCiMitigationRequest;
import uk.gov.di.ipv.core.library.cimit.domain.PutCiRequest;
import uk.gov.di.ipv.core.library.cimit.dto.ContraIndicatorCredentialDto;
import uk.gov.di.ipv.core.library.cimit.exception.CiPostMitigationsException;
import uk.gov.di.ipv.core.library.cimit.exception.CiPutException;
import uk.gov.di.ipv.core.library.cimit.exception.CiRetrievalException;
import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
import uk.gov.di.ipv.core.library.config.EnvironmentVariable;
import uk.gov.di.ipv.core.library.domain.ContraIndicatorItem;
import uk.gov.di.ipv.core.library.domain.ContraIndicators;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.cimitvc.CiMitJwt;
import uk.gov.di.ipv.core.library.domain.cimitvc.CiMitVc;
import uk.gov.di.ipv.core.library.domain.cimitvc.ContraIndicator;
import uk.gov.di.ipv.core.library.domain.cimitvc.EvidenceItem;
import uk.gov.di.ipv.core.library.exceptions.VerifiableCredentialException;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.validation.VerifiableCredentialJwtValidator;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.function.Function;
import java.util.stream.Collectors;

import static uk.gov.di.ipv.core.library.config.EnvironmentVariable.CIMIT_GET_CONTRAINDICATORS_LAMBDA_ARN;
import static uk.gov.di.ipv.core.library.config.EnvironmentVariable.CI_STORAGE_GET_LAMBDA_ARN;
import static uk.gov.di.ipv.core.library.config.EnvironmentVariable.CI_STORAGE_POST_MITIGATIONS_LAMBDA_ARN;
import static uk.gov.di.ipv.core.library.config.EnvironmentVariable.CI_STORAGE_PUT_LAMBDA_ARN;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_ERROR;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_ERROR_DESCRIPTION;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_MESSAGE_DESCRIPTION;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_PAYLOAD;
import static uk.gov.di.ipv.core.library.helpers.LogHelper.LogField.LOG_STATUS_CODE;

public class CiMitService {
    private static final Logger LOGGER = LogManager.getLogger();
    private static final Gson gson = new Gson();
    private static final String FAILED_LAMBDA_MESSAGE = "Lambda execution failed";
    private final AWSLambda lambdaClient;
    private final ConfigService configService;
    private final VerifiableCredentialJwtValidator verifiableCredentialJwtValidator;

    public CiMitService(ConfigService configService) {
        this.lambdaClient = AWSLambdaClientBuilder.defaultClient();
        this.configService = configService;
        this.verifiableCredentialJwtValidator = new VerifiableCredentialJwtValidator(configService);
    }

    public CiMitService(
            AWSLambda lambdaClient,
            ConfigService configService,
            VerifiableCredentialJwtValidator verifiableCredentialJwtValidator) {
        this.lambdaClient = lambdaClient;
        this.configService = configService;
        this.verifiableCredentialJwtValidator = verifiableCredentialJwtValidator;
    }

    public void submitVC(
            SignedJWT verifiableCredential, String govukSigninJourneyId, String ipAddress)
            throws CiPutException {
        InvokeRequest request =
                new InvokeRequest()
                        .withFunctionName(
                                configService.getEnvironmentVariable(CI_STORAGE_PUT_LAMBDA_ARN))
                        .withPayload(
                                gson.toJson(
                                        new PutCiRequest(
                                                govukSigninJourneyId,
                                                ipAddress,
                                                verifiableCredential.serialize())));

        LOGGER.info("Sending VC to CIMIT.");
        InvokeResult result = lambdaClient.invoke(request);

        if (lambdaExecutionFailed(result)) {
            logLambdaExecutionError(result, CI_STORAGE_PUT_LAMBDA_ARN);
            throw new CiPutException(FAILED_LAMBDA_MESSAGE);
        }
    }

    public void submitMitigatingVcList(
            List<String> verifiableCredentialList, String govukSigninJourneyId, String ipAddress)
            throws CiPostMitigationsException {
        InvokeRequest request =
                new InvokeRequest()
                        .withFunctionName(
                                configService.getEnvironmentVariable(
                                        CI_STORAGE_POST_MITIGATIONS_LAMBDA_ARN))
                        .withPayload(
                                gson.toJson(
                                        new PostCiMitigationRequest(
                                                govukSigninJourneyId,
                                                ipAddress,
                                                verifiableCredentialList)));

        LOGGER.info("Sending mitigating VCs to CIMIT.");
        InvokeResult result = lambdaClient.invoke(request);

        if (lambdaExecutionFailed(result)) {
            logLambdaExecutionError(result, CI_STORAGE_POST_MITIGATIONS_LAMBDA_ARN);
            throw new CiPostMitigationsException(FAILED_LAMBDA_MESSAGE);
        }
    }

    public List<ContraIndicatorItem> getCIs(
            String userId, String govukSigninJourneyId, String ipAddress)
            throws CiRetrievalException {
        InvokeResult result =
                invokeClientToGetCIResult(
                        CI_STORAGE_GET_LAMBDA_ARN,
                        govukSigninJourneyId,
                        ipAddress,
                        userId,
                        "Retrieving CIs from CIMIT.");
        String jsonResponse = new String(result.getPayload().array(), StandardCharsets.UTF_8);
        GetCiResponse response = gson.fromJson(jsonResponse, GetCiResponse.class);
        return response.getContraIndicators();
    }

    public ContraIndicators getContraIndicatorsVC(
            String userId, String govukSigninJourneyId, String ipAddress)
            throws CiRetrievalException {
        SignedJWT ciSignedJWT = getContraIndicatorsVCJwt(userId, govukSigninJourneyId, ipAddress);
        EvidenceItem contraIndicatorEvidence = parseContraIndicatorEvidence(ciSignedJWT);

        return mapToContraIndicators(contraIndicatorEvidence);
    }

    public SignedJWT getContraIndicatorsVCJwt(
            String userId, String govukSigninJourneyId, String ipAddress)
            throws CiRetrievalException {
        InvokeResult result =
                invokeClientToGetCIResult(
                        CIMIT_GET_CONTRAINDICATORS_LAMBDA_ARN,
                        govukSigninJourneyId,
                        ipAddress,
                        userId,
                        "Retrieving CIs from CIMIT system.");
        ContraIndicatorCredentialDto contraIndicatorCredential =
                gson.fromJson(
                        new String(result.getPayload().array(), StandardCharsets.UTF_8),
                        ContraIndicatorCredentialDto.class);
        return extractAndValidateContraIndicatorsJwt(contraIndicatorCredential.getVc(), userId);
    }

    private InvokeResult invokeClientToGetCIResult(
            EnvironmentVariable lambdaArnToInvoke,
            String govukSigninJourneyId,
            String ipAddress,
            String userId,
            String message)
            throws CiRetrievalException {
        LOGGER.info(message);
        InvokeRequest request =
                new InvokeRequest()
                        .withFunctionName(configService.getEnvironmentVariable(lambdaArnToInvoke))
                        .withPayload(
                                gson.toJson(
                                        new GetCiRequest(govukSigninJourneyId, ipAddress, userId)));

        InvokeResult result = null;
        try {
            result = lambdaClient.invoke(request);
        } catch (AWSLambdaException awsLEx) {
            LOGGER.error(
                    new StringMapMessage()
                            .with(
                                    LOG_MESSAGE_DESCRIPTION.getFieldName(),
                                    "AWSLambda client invocation failed.")
                            .with(LOG_ERROR_DESCRIPTION.getFieldName(), awsLEx.getMessage()));
            throw new CiRetrievalException(FAILED_LAMBDA_MESSAGE);
        }

        if (lambdaExecutionFailed(result)) {
            logLambdaExecutionError(result, lambdaArnToInvoke);
            throw new CiRetrievalException(FAILED_LAMBDA_MESSAGE);
        }
        return result;
    }

    private SignedJWT extractAndValidateContraIndicatorsJwt(
            String contraIndicatorsVC, String userId) throws CiRetrievalException {
        SignedJWT contraIndicatorsJwt;
        try {
            contraIndicatorsJwt = SignedJWT.parse(contraIndicatorsVC);
        } catch (ParseException e) {
            LOGGER.error(
                    new StringMapMessage()
                            .with(
                                    LOG_MESSAGE_DESCRIPTION.getFieldName(),
                                    "Failed to parse ContraIndicators JWT.")
                            .with(LOG_ERROR_DESCRIPTION.getFieldName(), e.getMessage()));
            throw new CiRetrievalException("Failed to parse JWT");
        }

        final String cimitComponentId =
                configService.getSsmParameter(ConfigurationVariable.CIMIT_COMPONENT_ID);
        final String cimitSigningKey =
                configService.getSsmParameter(ConfigurationVariable.CIMIT_SIGNING_KEY);
        try {
            verifiableCredentialJwtValidator.validateSignatureAndClaims(
                    contraIndicatorsJwt, ECKey.parse(cimitSigningKey), cimitComponentId, userId);
            LOGGER.info("ContraIndicators Verifiable Credential validated.");
        } catch (ParseException e) {
            LOGGER.error("Error parsing CIMIT signing key: '{}'", e.getMessage());
            throw new CiRetrievalException(
                    ErrorResponse.FAILED_TO_PARSE_CIMIT_SIGNING_KEY.getMessage());
        } catch (VerifiableCredentialException vcEx) {
            LOGGER.error(vcEx.getErrorResponse().getMessage());
            throw new CiRetrievalException(vcEx.getErrorResponse().getMessage());
        }

        return contraIndicatorsJwt;
    }

    private EvidenceItem parseContraIndicatorEvidence(SignedJWT signedJWT)
            throws CiRetrievalException {

        Map<String, Object> claimSetJsonObject;
        try {
            claimSetJsonObject = signedJWT.getJWTClaimsSet().toJSONObject();
        } catch (ParseException e) {
            String message = "Failed to parse ContraIndicators response json";
            LOGGER.error(
                    new StringMapMessage()
                            .with(LOG_MESSAGE_DESCRIPTION.getFieldName(), message)
                            .with(LOG_ERROR_DESCRIPTION.getFieldName(), e.getMessage()));
            throw new CiRetrievalException(message);
        }

        CiMitJwt ciMitJwt =
                gson.fromJson(
                        gson.toJson(claimSetJsonObject), new TypeToken<CiMitJwt>() {}.getType());

        CiMitVc vcClaim = ciMitJwt.getVc();
        if (vcClaim == null) {
            String message = "VC claim not found in CiMit JWT";
            LOGGER.error(
                    new StringMapMessage().with(LOG_ERROR_DESCRIPTION.getFieldName(), message));
            throw new CiRetrievalException(message);
        }

        List<EvidenceItem> evidenceList = vcClaim.getEvidence();
        if (evidenceList == null || evidenceList.size() != 1) {
            String message = "Unexpected evidence count";
            LOGGER.error(
                    new StringMapMessage()
                            .with(LOG_MESSAGE_DESCRIPTION.getFieldName(), message)
                            .with(
                                    LOG_ERROR_DESCRIPTION.getFieldName(),
                                    String.format(
                                            "Expected one evidence item, got %d",
                                            evidenceList == null ? 0 : evidenceList.size())));
            throw new CiRetrievalException(message);
        }

        return evidenceList.get(0);
    }

    private ContraIndicators mapToContraIndicators(EvidenceItem evidenceItem) {
        List<ContraIndicator> contraIndicators =
                evidenceItem.getContraIndicator() != null
                        ? evidenceItem.getContraIndicator()
                        : Collections.emptyList();
        return ContraIndicators.builder()
                .contraIndicatorsMap(
                        contraIndicators.stream()
                                .collect(
                                        Collectors.toMap(
                                                ContraIndicator::getCode, Function.identity())))
                .build();
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
