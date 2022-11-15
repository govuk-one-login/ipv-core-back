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
import uk.gov.di.ipv.core.library.domain.ContraIndicatorItem;
import uk.gov.di.ipv.core.library.exceptions.CiPostMitigationsException;
import uk.gov.di.ipv.core.library.exceptions.CiPutException;
import uk.gov.di.ipv.core.library.exceptions.CiRetrievalException;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.config.EnvironmentVariable.CI_STORAGE_GET_LAMBDA_ARN;
import static uk.gov.di.ipv.core.library.config.EnvironmentVariable.CI_STORAGE_POST_MITIGATIONS_LAMBDA_ARN;
import static uk.gov.di.ipv.core.library.config.EnvironmentVariable.CI_STORAGE_PUT_LAMBDA_ARN;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.SIGNED_VC_1;

@ExtendWith(MockitoExtension.class)
class CiStorageServiceTest {

    public static final String THE_ARN_OF_THE_PUT_LAMBDA = "the:arn:of:the:put:lambda";
    public static final String THE_ARN_OF_THE_POST_LAMBDA = "the:arn:of:the:post:lambda";
    public static final String THE_ARN_OF_THE_GET_LAMBDA = "the:arn:of:the:get:lambda";
    public static final String GOVUK_SIGNIN_JOURNEY_ID = "a-journey-id";
    public static final String TEST_USER_ID = "a-user-id";
    public static final String CLIENT_SOURCE_IP = "a-client-source-ip";
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

        ciStorageService.submitVC(
                SignedJWT.parse(SIGNED_VC_1), GOVUK_SIGNIN_JOURNEY_ID, CLIENT_SOURCE_IP);
        InvokeRequest request = requestCaptor.getValue();

        assertEquals(THE_ARN_OF_THE_PUT_LAMBDA, request.getFunctionName());
        assertEquals(
                String.format(
                        "{\"govuk_signin_journey_id\":\"%s\",\"ip_address\":\"%s\",\"signed_jwt\":\"%s\"}",
                        GOVUK_SIGNIN_JOURNEY_ID, CLIENT_SOURCE_IP, SIGNED_VC_1),
                new String(request.getPayload().array(), StandardCharsets.UTF_8));
    }

    @Test
    void submitVCThrowsIfLambdaExecutionFails() {
        InvokeResult result = new InvokeResult().withStatusCode(500);
        when(configurationService.getEnvironmentVariable(CI_STORAGE_PUT_LAMBDA_ARN))
                .thenReturn(THE_ARN_OF_THE_PUT_LAMBDA);
        when(lambdaClient.invoke(requestCaptor.capture())).thenReturn(result);

        assertThrows(
                CiPutException.class,
                () ->
                        ciStorageService.submitVC(
                                SignedJWT.parse(SIGNED_VC_1),
                                GOVUK_SIGNIN_JOURNEY_ID,
                                CLIENT_SOURCE_IP));
    }

    @Test
    void submitVCThrowsIfLambdaThrowsAnError() {
        InvokeResult result =
                new InvokeResult()
                        .withStatusCode(200)
                        .withFunctionError("Unhandled")
                        .withPayload(ByteBuffer.allocate(0));
        when(configurationService.getEnvironmentVariable(CI_STORAGE_PUT_LAMBDA_ARN))
                .thenReturn(THE_ARN_OF_THE_PUT_LAMBDA);
        when(lambdaClient.invoke(requestCaptor.capture())).thenReturn(result);

        assertThrows(
                CiPutException.class,
                () ->
                        ciStorageService.submitVC(
                                SignedJWT.parse(SIGNED_VC_1),
                                GOVUK_SIGNIN_JOURNEY_ID,
                                CLIENT_SOURCE_IP));
    }

    @Test
    void getCIsInvokesTheLambdaClientToGetTheItems() throws Exception {
        when(configurationService.getEnvironmentVariable(CI_STORAGE_GET_LAMBDA_ARN))
                .thenReturn(THE_ARN_OF_THE_GET_LAMBDA);
        when(lambdaClient.invoke(requestCaptor.capture()))
                .thenReturn(
                        new InvokeResult()
                                .withStatusCode(200)
                                .withPayload(
                                        ByteBuffer.wrap(
                                                String.format(
                                                                "{\"contraIndicators\":[{\"userId\":\"%s\",\"ci\":\"X01\"},{\"userId\":\"%<s\",\"ci\":\"Z02\"}]}",
                                                                TEST_USER_ID)
                                                        .getBytes(StandardCharsets.UTF_8))));

        List<ContraIndicatorItem> ciItems =
                ciStorageService.getCIs(TEST_USER_ID, GOVUK_SIGNIN_JOURNEY_ID, CLIENT_SOURCE_IP);
        InvokeRequest request = requestCaptor.getValue();

        assertEquals(THE_ARN_OF_THE_GET_LAMBDA, request.getFunctionName());
        assertEquals(
                String.format(
                        "{\"govuk_signin_journey_id\":\"%s\",\"ip_address\":\"%s\",\"user_id\":\"%s\"}",
                        GOVUK_SIGNIN_JOURNEY_ID, CLIENT_SOURCE_IP, TEST_USER_ID),
                new String(request.getPayload().array(), StandardCharsets.UTF_8));
        assertEquals(
                List.of(
                        new ContraIndicatorItem(TEST_USER_ID, null, null, null, "X01", null, null),
                        new ContraIndicatorItem(TEST_USER_ID, null, null, null, "Z02", null, null)),
                ciItems);
    }

    @Test
    void getCIsThrowsExceptionIfLambdaExecutionFails() {
        InvokeResult result = new InvokeResult().withStatusCode(500);
        when(configurationService.getEnvironmentVariable(CI_STORAGE_GET_LAMBDA_ARN))
                .thenReturn(THE_ARN_OF_THE_GET_LAMBDA);
        when(lambdaClient.invoke(requestCaptor.capture())).thenReturn(result);

        assertThrows(
                CiRetrievalException.class,
                () ->
                        ciStorageService.getCIs(
                                TEST_USER_ID, GOVUK_SIGNIN_JOURNEY_ID, CLIENT_SOURCE_IP));
    }

    @Test
    void getCIsThrowsExceptionIfLambdaThrowsError() {
        InvokeResult result =
                new InvokeResult()
                        .withStatusCode(200)
                        .withFunctionError("Unhandled")
                        .withPayload(ByteBuffer.allocate(0));
        when(configurationService.getEnvironmentVariable(CI_STORAGE_GET_LAMBDA_ARN))
                .thenReturn(THE_ARN_OF_THE_GET_LAMBDA);
        when(lambdaClient.invoke(requestCaptor.capture())).thenReturn(result);

        assertThrows(
                CiRetrievalException.class,
                () ->
                        ciStorageService.getCIs(
                                TEST_USER_ID, GOVUK_SIGNIN_JOURNEY_ID, CLIENT_SOURCE_IP));
    }

    @Test
    void submitMitigationVCInvokesTheLambdaClient() throws Exception {
        when(configurationService.getEnvironmentVariable(CI_STORAGE_POST_MITIGATIONS_LAMBDA_ARN))
                .thenReturn(THE_ARN_OF_THE_POST_LAMBDA);
        when(lambdaClient.invoke(requestCaptor.capture()))
                .thenReturn(new InvokeResult().withStatusCode(200));

        ciStorageService.submitMitigatingVcList(
                List.of(SIGNED_VC_1), GOVUK_SIGNIN_JOURNEY_ID, CLIENT_SOURCE_IP);
        InvokeRequest request = requestCaptor.getValue();

        assertEquals(THE_ARN_OF_THE_POST_LAMBDA, request.getFunctionName());
        assertEquals(
                String.format(
                        "{\"govuk_signin_journey_id\":\"%s\",\"ip_address\":\"%s\",\"signed_jwt_list\":[\"%s\"]}",
                        GOVUK_SIGNIN_JOURNEY_ID, CLIENT_SOURCE_IP, SIGNED_VC_1),
                new String(request.getPayload().array(), StandardCharsets.UTF_8));
    }

    @Test
    void submitMitigationVCThrowsIfLambdaExecutionFails() {
        InvokeResult result = new InvokeResult().withStatusCode(500);
        when(configurationService.getEnvironmentVariable(CI_STORAGE_POST_MITIGATIONS_LAMBDA_ARN))
                .thenReturn(THE_ARN_OF_THE_POST_LAMBDA);
        when(lambdaClient.invoke(requestCaptor.capture())).thenReturn(result);

        assertThrows(
                CiPostMitigationsException.class,
                () ->
                        ciStorageService.submitMitigatingVcList(
                                List.of(SIGNED_VC_1), GOVUK_SIGNIN_JOURNEY_ID, CLIENT_SOURCE_IP));
    }

    @Test
    void submitMitigationVCThrowsIfLambdaThrowsAnError() {
        InvokeResult result =
                new InvokeResult()
                        .withStatusCode(200)
                        .withFunctionError("Unhandled")
                        .withPayload(ByteBuffer.allocate(0));
        when(configurationService.getEnvironmentVariable(CI_STORAGE_POST_MITIGATIONS_LAMBDA_ARN))
                .thenReturn(THE_ARN_OF_THE_POST_LAMBDA);
        when(lambdaClient.invoke(requestCaptor.capture())).thenReturn(result);

        assertThrows(
                CiPostMitigationsException.class,
                () ->
                        ciStorageService.submitMitigatingVcList(
                                List.of(SIGNED_VC_1), GOVUK_SIGNIN_JOURNEY_ID, CLIENT_SOURCE_IP));
    }
}
