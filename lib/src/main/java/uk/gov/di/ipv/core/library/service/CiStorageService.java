package uk.gov.di.ipv.core.library.service;

import com.amazonaws.services.lambda.AWSLambda;
import com.amazonaws.services.lambda.AWSLambdaClientBuilder;
import com.amazonaws.services.lambda.model.InvokeRequest;
import com.amazonaws.services.lambda.model.InvokeResult;
import com.google.gson.Gson;
import com.nimbusds.jwt.SignedJWT;
import org.apache.http.HttpStatus;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.message.StringMapMessage;
import uk.gov.di.ipv.core.library.domain.ContraIndicatorItem;
import uk.gov.di.ipv.core.library.domain.GetCiRequest;
import uk.gov.di.ipv.core.library.domain.GetCiResponse;
import uk.gov.di.ipv.core.library.domain.PutCiRequest;
import uk.gov.di.ipv.core.library.exceptions.CiRetrievalException;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;

import static uk.gov.di.ipv.core.library.config.EnvironmentVariable.CI_STORAGE_GET_LAMBDA_ARN;
import static uk.gov.di.ipv.core.library.config.EnvironmentVariable.CI_STORAGE_PUT_LAMBDA_ARN;

public class CiStorageService {
    private static final Logger LOGGER = LogManager.getLogger();
    private static final Gson gson = new Gson();
    private final AWSLambda lambdaClient;
    private final ConfigurationService configurationService;

    public CiStorageService(ConfigurationService configurationService) {
        this.lambdaClient = AWSLambdaClientBuilder.defaultClient();
        this.configurationService = configurationService;
    }

    public CiStorageService(AWSLambda lambdaClient, ConfigurationService configurationService) {
        this.lambdaClient = lambdaClient;
        this.configurationService = configurationService;
    }

    public void submitVC(SignedJWT verifiableCredential, String govukSigninJourneyId) {
        InvokeRequest request =
                new InvokeRequest()
                        .withFunctionName(
                                configurationService.getEnvironmentVariable(
                                        CI_STORAGE_PUT_LAMBDA_ARN))
                        .withPayload(
                                gson.toJson(
                                        new PutCiRequest(
                                                govukSigninJourneyId,
                                                verifiableCredential.serialize())));

        LOGGER.info("Sending VC to CI storage system");
        InvokeResult result = lambdaClient.invoke(request);

        if (lambdaExecutionFailed(result)) {
            logLambdaExecutionError(result);
        }
    }

    public List<ContraIndicatorItem> getCIs(String userId, String govukSigninJourneyId)
            throws CiRetrievalException {
        InvokeRequest request =
                new InvokeRequest()
                        .withFunctionName(
                                configurationService.getEnvironmentVariable(
                                        CI_STORAGE_GET_LAMBDA_ARN))
                        .withPayload(gson.toJson(new GetCiRequest(govukSigninJourneyId, userId)));

        LOGGER.info("Retrieving CIs from CI storage system");
        InvokeResult result = lambdaClient.invoke(request);

        if (lambdaExecutionFailed(result)) {
            logLambdaExecutionError(result);
            throw new CiRetrievalException("Lambda execution failed");
        }

        String jsonResponse = new String(result.getPayload().array(), StandardCharsets.UTF_8);
        GetCiResponse response = gson.fromJson(jsonResponse, GetCiResponse.class);

        return response.getContraIndicators();
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
        message.put("message", "CI storage lambda execution failed");
        message.put("error", result.getFunctionError());
        message.put("statusCode", String.valueOf(result.getStatusCode()));
        message.put("payload", getPayloadOrNull(result));
        message.values().removeAll(Collections.singleton(null));
        LOGGER.error(new StringMapMessage(message));
    }
}
