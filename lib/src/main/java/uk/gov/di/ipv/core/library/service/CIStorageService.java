package uk.gov.di.ipv.core.library.service;

import com.amazonaws.services.lambda.AWSLambda;
import com.amazonaws.services.lambda.AWSLambdaClientBuilder;
import com.amazonaws.services.lambda.model.InvokeRequest;
import com.amazonaws.services.lambda.model.InvokeResult;
import com.google.gson.Gson;
import com.nimbusds.jwt.SignedJWT;
import org.apache.http.HttpStatus;
import org.apache.logging.log4j.Level;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.ipv.core.library.domain.PutCiRequest;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
import uk.gov.di.ipv.core.library.helpers.LogHelper.LogField;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

import static uk.gov.di.ipv.core.library.config.EnvironmentVariable.CI_STORAGE_PUT_LAMBDA_ARN;

public class CIStorageService {
    private static final Logger LOGGER = LogManager.getLogger();
    private static final Gson gson = new Gson();
    private final AWSLambda lambdaClient;
    private final ConfigurationService configurationService;

    public CIStorageService(ConfigurationService configurationService) {
        this.lambdaClient = AWSLambdaClientBuilder.defaultClient();
        this.configurationService = configurationService;
    }

    public CIStorageService(AWSLambda lambdaClient, ConfigurationService configurationService) {
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

        LOGGER.info("Sending VC to CI storage");
        InvokeResult result = lambdaClient.invoke(request);

        if (lambdaExecutionFailed(result)) {
            LogHelper.logMessageWithFieldsAndValues(
                    Level.ERROR,
                    "CI storage lambda execution failed",
                    LogField.ERROR,
                    result.getFunctionError(),
                    LogField.STATUS_CODE,
                    String.valueOf(result.getStatusCode()),
                    LogField.PAYLOAD,
                    getPayloadOrNone(result));
        }
    }

    private boolean lambdaExecutionFailed(InvokeResult result) {
        return result.getStatusCode() != HttpStatus.SC_OK || result.getFunctionError() != null;
    }

    private String getPayloadOrNone(InvokeResult result) {
        ByteBuffer payload = result.getPayload();
        return payload == null ? "none" : new String(payload.array(), StandardCharsets.UTF_8);
    }
}
