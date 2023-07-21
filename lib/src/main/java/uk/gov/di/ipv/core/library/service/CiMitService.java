package uk.gov.di.ipv.core.library.service;

import com.amazonaws.services.lambda.AWSLambda;
import com.amazonaws.services.lambda.AWSLambdaClientBuilder;
import com.amazonaws.services.lambda.model.AWSLambdaException;
import com.amazonaws.services.lambda.model.InvokeRequest;
import com.amazonaws.services.lambda.model.InvokeResult;
import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.shaded.json.JSONArray;
import com.nimbusds.jose.shaded.json.JSONObject;
import com.nimbusds.jwt.SignedJWT;
import org.apache.http.HttpStatus;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.message.StringMapMessage;
import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
import uk.gov.di.ipv.core.library.config.EnvironmentVariable;
import uk.gov.di.ipv.core.library.domain.ContraIndications;
import uk.gov.di.ipv.core.library.domain.ContraIndicator;
import uk.gov.di.ipv.core.library.domain.ContraIndicatorItem;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.GetCiRequest;
import uk.gov.di.ipv.core.library.domain.GetCiResponse;
import uk.gov.di.ipv.core.library.domain.MitigatingCredential;
import uk.gov.di.ipv.core.library.domain.Mitigation;
import uk.gov.di.ipv.core.library.domain.PostCiMitigationRequest;
import uk.gov.di.ipv.core.library.domain.PutCiRequest;
import uk.gov.di.ipv.core.library.dto.ContraIndicatorDto;
import uk.gov.di.ipv.core.library.dto.ContraIndicatorEvidenceDto;
import uk.gov.di.ipv.core.library.dto.MitigationCredentialDto;
import uk.gov.di.ipv.core.library.dto.MitigationDto;
import uk.gov.di.ipv.core.library.exceptions.CiPostMitigationsException;
import uk.gov.di.ipv.core.library.exceptions.CiPutException;
import uk.gov.di.ipv.core.library.exceptions.CiRetrievalException;
import uk.gov.di.ipv.core.library.exceptions.VerifiableCredentialException;
import uk.gov.di.ipv.core.library.validation.VerifiableCredentialJwtValidator;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.time.Instant;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Objects;
import java.util.function.Function;
import java.util.stream.Collectors;

import static uk.gov.di.ipv.core.library.config.EnvironmentVariable.CIMIT_GET_CONTRAINDICATORS_LAMBDA_ARN;
import static uk.gov.di.ipv.core.library.config.EnvironmentVariable.CI_STORAGE_GET_LAMBDA_ARN;
import static uk.gov.di.ipv.core.library.config.EnvironmentVariable.CI_STORAGE_POST_MITIGATIONS_LAMBDA_ARN;
import static uk.gov.di.ipv.core.library.config.EnvironmentVariable.CI_STORAGE_PUT_LAMBDA_ARN;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_CLAIM;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_EVIDENCE;
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

    public ContraIndications getContraIndicatorsVC(
            String userId, String govukSigninJourneyId, String ipAddress)
            throws CiRetrievalException {
        InvokeResult result =
                invokeClientToGetCIResult(
                        CIMIT_GET_CONTRAINDICATORS_LAMBDA_ARN,
                        govukSigninJourneyId,
                        ipAddress,
                        userId,
                        "Retrieving CIs from CIMIT system.");
        SignedJWT ciSignedJWT = extractAndValidateContraIndicatorsJwt(result, userId);
        ContraIndicatorEvidenceDto contraIndicatorEvidence =
                parseContraIndicatorEvidence(ciSignedJWT);

        return mapToContraIndications(contraIndicatorEvidence);
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
            InvokeResult contraIndicatorsResult, String userId) throws CiRetrievalException {
        final String contraIndicatorsVC =
                new String(contraIndicatorsResult.getPayload().array(), StandardCharsets.UTF_8);

        SignedJWT contraIndicatorsJwt;
        try {
            // TODO: The JWT is quoted - don't think it should be?
            contraIndicatorsJwt = SignedJWT.parse(contraIndicatorsVC.replace("\"", ""));
            LOGGER.info(contraIndicatorsJwt.serialize());
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

    private ContraIndicatorEvidenceDto parseContraIndicatorEvidence(SignedJWT signedJWT)
            throws CiRetrievalException {
        JSONObject vcClaim;
        try {
            vcClaim = (JSONObject) signedJWT.getJWTClaimsSet().getClaim(VC_CLAIM);
        } catch (ParseException e) {
            String message = "Failed to parse ContraIndicators response json";
            LOGGER.error(
                    new StringMapMessage()
                            .with(LOG_MESSAGE_DESCRIPTION.getFieldName(), message)
                            .with(LOG_ERROR_DESCRIPTION.getFieldName(), e.getMessage()));
            throw new CiRetrievalException(message);
        }

        JSONArray evidenceArray = (JSONArray) vcClaim.get(VC_EVIDENCE);
        if (evidenceArray == null || evidenceArray.size() != 1) {
            String message = "Unexpected evidence count.";
            LOGGER.error(
                    new StringMapMessage()
                            .with(LOG_MESSAGE_DESCRIPTION.getFieldName(), message)
                            .with(
                                    LOG_ERROR_DESCRIPTION.getFieldName(),
                                    String.format(
                                            "Expected one evidence item, got %d.",
                                            evidenceArray == null ? 0 : evidenceArray.size())));
            throw new CiRetrievalException(message);
        }

        List<ContraIndicatorEvidenceDto> contraIndicatorEvidenceDtos =
                gson.fromJson(
                        evidenceArray.toJSONString(),
                        new TypeToken<List<ContraIndicatorEvidenceDto>>() {}.getType());
        return contraIndicatorEvidenceDtos.get(0);
    }

    private ContraIndications mapToContraIndications(
            ContraIndicatorEvidenceDto contraIndicatorEvidenceDto) {
        List<ContraIndicatorDto> contraIndicators =
                contraIndicatorEvidenceDto.getCi() != null
                        ? contraIndicatorEvidenceDto.getCi()
                        : Collections.emptyList();
        return ContraIndications.builder()
                .contraIndicators(
                        contraIndicators.stream()
                                .map(this::mapToContraIndicator)
                                .collect(
                                        Collectors.toMap(
                                                ContraIndicator::getCode, Function.identity())))
                .build();
    }

    private ContraIndicator mapToContraIndicator(ContraIndicatorDto contraIndicatorDto) {
        return ContraIndicator.builder()
                .code(contraIndicatorDto.getCode())
                .transactionIds(contraIndicatorDto.getTxn())
                .documentId(contraIndicatorDto.getDocument())
                .issuanceDate(Instant.parse(contraIndicatorDto.getIssuanceDate()))
                .mitigations(mapToMitigations(contraIndicatorDto.getMitigation()))
                .incompleteMitigations(
                        mapToMitigations(contraIndicatorDto.getIncompleteMitigation()))
                .build();
    }

    private List<Mitigation> mapToMitigations(List<MitigationDto> mitigationDtos) {
        return mitigationDtos != null
                ? mitigationDtos.stream()
                        .map(
                                mitigationDto ->
                                        Mitigation.builder()
                                                .code(mitigationDto.getCode())
                                                .mitigatingCredentials(
                                                        mitigationDto
                                                                .getMitigatingCredential()
                                                                .stream()
                                                                .map(
                                                                        this
                                                                                ::mapToMitigatingCredential)
                                                                .collect(Collectors.toList()))
                                                .build())
                        .collect(Collectors.toList())
                : Collections.emptyList();
    }

    private MitigatingCredential mapToMitigatingCredential(
            MitigationCredentialDto mitigationCredentialDto) {
        return MitigatingCredential.builder()
                .issuer(mitigationCredentialDto.getIssuer())
                .id(mitigationCredentialDto.getId())
                .validFrom(Instant.parse(mitigationCredentialDto.getValidFrom()))
                .transactionId(mitigationCredentialDto.getTxn())
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
