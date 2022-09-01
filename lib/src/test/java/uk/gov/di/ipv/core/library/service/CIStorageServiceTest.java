package uk.gov.di.ipv.core.library.service;

import com.amazonaws.services.lambda.AWSLambda;
import com.amazonaws.services.lambda.model.InvokeRequest;
import com.amazonaws.services.lambda.model.InvokeResult;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.config.EnvironmentVariable.CI_STORAGE_PUT_LAMBDA_ARN;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.SIGNED_VC_1;

@ExtendWith(MockitoExtension.class)
class CiStorageServiceTest {

    public static final String THE_ARN_OF_THE_PUT_LAMBDA = "the:arn:of:the:put:lambda";
    public static final String GOVUK_SIGNIN_JOURNEY_ID = "a-journey-id";
    @Captor ArgumentCaptor<InvokeRequest> requestCaptor;

    @Mock AWSLambda lambdaClient;
    @Mock ConfigurationService configurationService;
    @InjectMocks CiStorageService ciStorageService;

    @Test
    void submitVCInvokesTheLambdaClient() throws Exception {
        when(configurationService.getEnvironmentVariable(CI_STORAGE_PUT_LAMBDA_ARN))
                .thenReturn(THE_ARN_OF_THE_PUT_LAMBDA);
        when(lambdaClient.invoke(requestCaptor.capture()))
                .thenReturn(new InvokeResult().withStatusCode(200));

        ciStorageService.submitVC(SignedJWT.parse(SIGNED_VC_1), GOVUK_SIGNIN_JOURNEY_ID);
        InvokeRequest request = requestCaptor.getValue();

        assertEquals(THE_ARN_OF_THE_PUT_LAMBDA, request.getFunctionName());
        assertEquals(
                String.format(
                        "{\"govuk_signin_journey_id\":\"%s\",\"signed_jwt\":\"%s\"}",
                        GOVUK_SIGNIN_JOURNEY_ID, SIGNED_VC_1),
                new String(request.getPayload().array(), StandardCharsets.UTF_8));
    }

    @Test
    void submitVCDoesNotThrowIfLambdaExecutionFails() {
        InvokeResult result = new InvokeResult().withStatusCode(500);
        when(configurationService.getEnvironmentVariable(CI_STORAGE_PUT_LAMBDA_ARN))
                .thenReturn(THE_ARN_OF_THE_PUT_LAMBDA);
        when(lambdaClient.invoke(requestCaptor.capture())).thenReturn(result);

        assertDoesNotThrow(
                () ->
                        ciStorageService.submitVC(
                                SignedJWT.parse(SIGNED_VC_1), GOVUK_SIGNIN_JOURNEY_ID));
    }

    @Test
    void submitVCDoesNotThrowIfLambdaThrowsAnError() {
        InvokeResult result =
                new InvokeResult()
                        .withStatusCode(200)
                        .withFunctionError("Unhandled")
                        .withPayload(ByteBuffer.allocate(0));
        when(configurationService.getEnvironmentVariable(CI_STORAGE_PUT_LAMBDA_ARN))
                .thenReturn(THE_ARN_OF_THE_PUT_LAMBDA);
        when(lambdaClient.invoke(requestCaptor.capture())).thenReturn(result);

        assertDoesNotThrow(
                () ->
                        ciStorageService.submitVC(
                                SignedJWT.parse(SIGNED_VC_1), GOVUK_SIGNIN_JOURNEY_ID));
    }
}
