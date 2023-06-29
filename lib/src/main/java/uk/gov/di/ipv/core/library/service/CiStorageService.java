package uk.gov.di.ipv.core.library.service;

import com.amazonaws.services.lambda.AWSLambda;
import com.amazonaws.services.lambda.AWSLambdaClientBuilder;
import com.amazonaws.services.lambda.model.AWSLambdaException;
import com.amazonaws.services.lambda.model.InvokeRequest;
import com.amazonaws.services.lambda.model.InvokeResult;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.google.gson.Gson;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.shaded.json.JSONArray;
import com.nimbusds.jose.shaded.json.JSONObject;
import com.nimbusds.jwt.SignedJWT;
import org.apache.http.HttpStatus;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.message.StringMapMessage;
import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
import uk.gov.di.ipv.core.library.domain.ContraIndications;
import uk.gov.di.ipv.core.library.domain.ContraIndicator;
import uk.gov.di.ipv.core.library.domain.ContraIndicatorItem;
import uk.gov.di.ipv.core.library.domain.GetCiRequest;
import uk.gov.di.ipv.core.library.domain.GetCiResponse;
import uk.gov.di.ipv.core.library.domain.MitigatingCredential;
import uk.gov.di.ipv.core.library.domain.Mitigation;
import uk.gov.di.ipv.core.library.domain.PostCiMitigationRequest;
import uk.gov.di.ipv.core.library.domain.PutCiRequest;
import uk.gov.di.ipv.core.library.dto.ContraIndicatorDto;
import uk.gov.di.ipv.core.library.dto.ContraIndicatorEvidenceDto;
import uk.gov.di.ipv.core.library.dto.ContraIndicatorMitigatingCredentialDto;
import uk.gov.di.ipv.core.library.dto.ContraIndicatorMitigationDto;
import uk.gov.di.ipv.core.library.dto.ContraIndicatorsVC;
import uk.gov.di.ipv.core.library.exceptions.CiPostMitigationsException;
import uk.gov.di.ipv.core.library.exceptions.CiPutException;
import uk.gov.di.ipv.core.library.exceptions.CiRetrievalException;
import uk.gov.di.ipv.core.library.validation.VerifiableCredentialJwtValidator;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.text.ParseException;
import java.time.Instant;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
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

public class CiStorageService {
    private static final Logger LOGGER = LogManager.getLogger();
    private static final Gson gson = new Gson();
    private static final String FAILED_LAMBDA_MESSAGE = "Lambda execution failed";
    private static final String FAILED_PARSE_MESSAGE = "Failed to parse JWT";
    private static final String UNEXPECTED_EVIDENCE = "Unexpected evidence";
    private static final String FAILED_DESERIALISATION_MESSAGE = "Failed to deserialise JSON";
    private final AWSLambda lambdaClient;
    private final ConfigService configService;

    public CiStorageService(ConfigService configService) {
        this.lambdaClient = AWSLambdaClientBuilder.defaultClient();
        this.configService = configService;
    }

    public CiStorageService(AWSLambda lambdaClient, ConfigService configService) {
        this.lambdaClient = lambdaClient;
        this.configService = configService;
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

        LOGGER.info("Sending VC to CI storage system.");
        InvokeResult result = lambdaClient.invoke(request);

        if (lambdaExecutionFailed(result)) {
            logLambdaExecutionError(result);
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

        LOGGER.info("Sending mitigating VC's to CI storage system.");
        InvokeResult result = lambdaClient.invoke(request);

        if (lambdaExecutionFailed(result)) {
            logLambdaExecutionError(result);
            throw new CiPostMitigationsException(FAILED_LAMBDA_MESSAGE);
        }
    }

    public List<ContraIndicatorItem> getCIs(
            String userId, String govukSigninJourneyId, String ipAddress)
            throws CiRetrievalException {
        InvokeRequest request =
                new InvokeRequest()
                        .withFunctionName(
                                configService.getEnvironmentVariable(CI_STORAGE_GET_LAMBDA_ARN))
                        .withPayload(
                                gson.toJson(
                                        new GetCiRequest(govukSigninJourneyId, ipAddress, userId)));

        LOGGER.info("Retrieving CIs from CI storage system.");
        InvokeResult result = lambdaClient.invoke(request);

        if (lambdaExecutionFailed(result)) {
            logLambdaExecutionError(result);
            throw new CiRetrievalException(FAILED_LAMBDA_MESSAGE);
        }

        String jsonResponse = new String(result.getPayload().array(), StandardCharsets.UTF_8);
        GetCiResponse response = gson.fromJson(jsonResponse, GetCiResponse.class);
        return response.getContraIndicators();
    }

    public ContraIndications getContraIndicatorsVC(
            String userId, String govukSigninJourneyId, String ipAddress)
            throws CiRetrievalException, ParseException {
        final InvokeResult contraIndicatorsResult =
                invokeGetContraIndicatorsCredential(userId, govukSigninJourneyId, ipAddress);

        final SignedJWT contraIndicatorsJwt =
                extractAndValidateContraIndicatorsJwt(contraIndicatorsResult, userId);

        final ContraIndicatorEvidenceDto contraIndicatorEvidence =
                extractContraIndicatorEvidence(contraIndicatorsJwt);

        return buildContraIndications(contraIndicatorEvidence);
    }

    private InvokeResult invokeGetContraIndicatorsCredential(
            String userId, String govukSigninJourneyId, String ipAddress)
            throws CiRetrievalException {
        final InvokeRequest request =
                new InvokeRequest()
                        .withFunctionName(
                                configService.getEnvironmentVariable(
                                        CIMIT_GET_CONTRAINDICATORS_LAMBDA_ARN))
                        .withPayload(
                                gson.toJson(
                                        new GetCiRequest(govukSigninJourneyId, ipAddress, userId)));
        LOGGER.info("Retrieving ContraIndicator VC from CIMIT.");
        InvokeResult result;
        try {
            result = lambdaClient.invoke(request);
        } catch (AWSLambdaException e) {
            LOGGER.error(
                    new StringMapMessage()
                            .with(
                                    LOG_MESSAGE_DESCRIPTION.getFieldName(),
                                    "CIMIT getContraindicators execution failed.")
                            .with(LOG_ERROR_DESCRIPTION.getFieldName(), e.getMessage()));
            throw new CiRetrievalException(FAILED_LAMBDA_MESSAGE);
        }

        if (lambdaExecutionFailed(result)) {
            logLambdaExecutionError(result);
            throw new CiRetrievalException(FAILED_LAMBDA_MESSAGE);
        }
        return result;
    }

    private SignedJWT extractAndValidateContraIndicatorsJwt(
            InvokeResult contraIndicatorsResult, String userId)
            throws CiRetrievalException, ParseException {
        final String jsonResponse =
                new String(contraIndicatorsResult.getPayload().array(), StandardCharsets.UTF_8);
        final ContraIndicatorsVC contraIndicatorsVC =
                gson.fromJson(jsonResponse, ContraIndicatorsVC.class);

        SignedJWT contraIndicatorsJwt;
        try {
            contraIndicatorsJwt = SignedJWT.parse(contraIndicatorsVC.getSignedJwt());
        } catch (ParseException e) {
            LOGGER.error(
                    new StringMapMessage()
                            .with(
                                    LOG_MESSAGE_DESCRIPTION.getFieldName(),
                                    "Failed to parse ContraIndicators JWT.")
                            .with(LOG_ERROR_DESCRIPTION.getFieldName(), e.getMessage()));
            throw new CiRetrievalException(FAILED_PARSE_MESSAGE);
        }

        final String cimitComponentId =
                configService.getSsmParameter(ConfigurationVariable.CIMIT_COMPONENT_ID);
        final String cimitSigningKey =
                configService.getSsmParameter(ConfigurationVariable.CIMIT_SIGNING_KEY);

        (new VerifiableCredentialJwtValidator())
                .validate(
                        contraIndicatorsJwt,
                        cimitComponentId,
                        ECKey.parse(cimitSigningKey),
                        userId);

        return contraIndicatorsJwt;
    }

    private ContraIndicatorEvidenceDto extractContraIndicatorEvidence(SignedJWT contraIndicatorsJwt)
            throws CiRetrievalException {
        JSONObject vcClaim;
        try {
            vcClaim = (JSONObject) contraIndicatorsJwt.getJWTClaimsSet().getClaim(VC_CLAIM);
        } catch (ParseException e) {
            LOGGER.error(
                    new StringMapMessage()
                            .with(
                                    LOG_MESSAGE_DESCRIPTION.getFieldName(),
                                    "Failed to parse ContraIndicators Verifiable Credential claims set.")
                            .with(LOG_ERROR_DESCRIPTION.getFieldName(), e.getMessage()));
            throw new CiRetrievalException(FAILED_PARSE_MESSAGE);
        }
        // TODO: Should we validate the Verifiable Credential Type as
        // [SecurityCheckCredential,VerifiableCredential]

        final JSONArray evidence = (JSONArray) vcClaim.get(VC_EVIDENCE);

        // TODO: Check if 0 or >1 are valid scenarios
        if (evidence.size() != 1) {
            LOGGER.error(
                    new StringMapMessage()
                            .with(
                                    LOG_MESSAGE_DESCRIPTION.getFieldName(),
                                    "Unexpected evidence count.")
                            .with(
                                    LOG_ERROR_DESCRIPTION.getFieldName(),
                                    String.format(
                                            "Expected 1 evidence item, got %d.", evidence.size())));
            throw new CiRetrievalException(UNEXPECTED_EVIDENCE);
        }

        try {
            return (new ObjectMapper())
                    .readerFor(ContraIndicatorEvidenceDto.class)
                    .readValue(evidence.get(0).toString());
        } catch (JsonProcessingException e) {
            LOGGER.error(
                    new StringMapMessage()
                            .with(
                                    LOG_MESSAGE_DESCRIPTION.getFieldName(),
                                    "Failed to deserialise CIMIT ContraIndicator VC.")
                            .with(LOG_ERROR_DESCRIPTION.getFieldName(), e.getMessage()));
            throw new CiRetrievalException(FAILED_DESERIALISATION_MESSAGE);
        }
    }

    private boolean lambdaExecutionFailed(InvokeResult result) {
        return result.getStatusCode() != HttpStatus.SC_OK || result.getFunctionError() != null;
    }

    private String getPayloadOrNull(InvokeResult result) {
        ByteBuffer payload = result.getPayload();
        return payload == null ? null : new String(payload.array(), StandardCharsets.UTF_8);
    }

    private void logLambdaExecutionError(InvokeResult result) {
        HashMap<String, String> message = new HashMap<>();
        message.put(LOG_MESSAGE_DESCRIPTION.getFieldName(), "CI storage lambda execution failed.");
        message.put(LOG_ERROR.getFieldName(), result.getFunctionError());
        message.put(LOG_STATUS_CODE.getFieldName(), String.valueOf(result.getStatusCode()));
        message.put(LOG_PAYLOAD.getFieldName(), getPayloadOrNull(result));
        message.values().removeAll(Collections.singleton(null));
        LOGGER.error(new StringMapMessage(message));
    }

    private ContraIndications buildContraIndications(
            ContraIndicatorEvidenceDto contraIndicatorEvidenceDto) {
        return ContraIndications.builder()
                .contraIndicatorMap(
                        contraIndicatorEvidenceDto.getContraIndicator().stream()
                                .map(this::buildContraIndicator)
                                .collect(
                                        Collectors.toMap(
                                                ContraIndicator::getContraIndicatorCode,
                                                Function.identity())))
                .build();
    }

    private ContraIndicator buildContraIndicator(ContraIndicatorDto contraIndicatorDto) {
        return ContraIndicator.builder()
                .contraIndicatorCode(contraIndicatorDto.getCode())
                .transactionIds(contraIndicatorDto.getTxns())
                .documentId(contraIndicatorDto.getDocument())
                .issuanceDate(Instant.parse(contraIndicatorDto.getIssuanceDate()))
                .mitigations(buildMitigationList(contraIndicatorDto.getCompleteMitigations()))
                .incompleteMitigations(
                        buildMitigationList(contraIndicatorDto.getIncompleteMitigations()))
                .build();
    }

    private List<Mitigation> buildMitigationList(List<ContraIndicatorMitigationDto> mitigations) {
        return mitigations.stream()
                .map(
                        contraIndicatorMitigationDto ->
                                Mitigation.builder()
                                        .mitigationCode(contraIndicatorMitigationDto.getCode())
                                        .mitigatingCredentials(
                                                contraIndicatorMitigationDto
                                                        .getMitigatingCredentials()
                                                        .stream()
                                                        .map(this::buildMitigatingCredential)
                                                        .collect(Collectors.toList()))
                                        .build())
                .collect(Collectors.toList());
    }

    private MitigatingCredential buildMitigatingCredential(
            ContraIndicatorMitigatingCredentialDto mitigatingCredential) {
        return MitigatingCredential.builder()
                .issuer(mitigatingCredential.getIssuer())
                .userId(mitigatingCredential.getUserId())
                .validFrom(Instant.parse(mitigatingCredential.getValidFrom()))
                .transactionId(mitigatingCredential.getTxn())
                .build();
    }
}
