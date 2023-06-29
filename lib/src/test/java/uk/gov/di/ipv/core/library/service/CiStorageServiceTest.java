package uk.gov.di.ipv.core.library.service;

import com.amazonaws.services.lambda.AWSLambda;
import com.amazonaws.services.lambda.model.AWSLambdaException;
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
import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
import uk.gov.di.ipv.core.library.domain.ContraIndications;
import uk.gov.di.ipv.core.library.domain.ContraIndicatorItem;
import uk.gov.di.ipv.core.library.exceptions.CiPostMitigationsException;
import uk.gov.di.ipv.core.library.exceptions.CiPutException;
import uk.gov.di.ipv.core.library.exceptions.CiRetrievalException;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.config.EnvironmentVariable.CIMIT_GET_CONTRAINDICATORS_LAMBDA_ARN;
import static uk.gov.di.ipv.core.library.config.EnvironmentVariable.CI_STORAGE_GET_LAMBDA_ARN;
import static uk.gov.di.ipv.core.library.config.EnvironmentVariable.CI_STORAGE_POST_MITIGATIONS_LAMBDA_ARN;
import static uk.gov.di.ipv.core.library.config.EnvironmentVariable.CI_STORAGE_PUT_LAMBDA_ARN;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.EC_PUBLIC_JWK;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.SIGNED_CONTRA_INDICATOR_VC;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.SIGNED_CONTRA_INDICATOR_VC_INVALID_EVIDENCE;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.SIGNED_CONTRA_INDICATOR_VC_NO_EVIDENCE;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.SIGNED_VC_1;

@ExtendWith(MockitoExtension.class)
class CiStorageServiceTest {

    private static final String THE_ARN_OF_THE_PUT_LAMBDA = "the:arn:of:the:put:lambda";
    private static final String THE_ARN_OF_THE_POST_LAMBDA = "the:arn:of:the:post:lambda";
    private static final String THE_ARN_OF_THE_GET_LAMBDA = "the:arn:of:the:get:lambda";

    private static final String TEST_CIMIT_GET_CONTRAINDICATORS_LAMBDA_ARN =
            "arn:of:getContraIndicatorCredential";
    private static final String GOVUK_SIGNIN_JOURNEY_ID = "a-journey-id";
    private static final String TEST_USER_ID = "a-user-id";
    private static final String CLIENT_SOURCE_IP = "a-client-source-ip";

    private static final String NOT_A_JWT = "not.a.jwt";
    @Captor ArgumentCaptor<InvokeRequest> requestCaptor;

    @Mock AWSLambda lambdaClient;
    @Mock ConfigService configService;
    @InjectMocks CiStorageService ciStorageService;

    @Test
    void submitVCInvokesTheLambdaClient() throws Exception {
        when(configService.getEnvironmentVariable(CI_STORAGE_PUT_LAMBDA_ARN))
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
        when(configService.getEnvironmentVariable(CI_STORAGE_PUT_LAMBDA_ARN))
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
        when(configService.getEnvironmentVariable(CI_STORAGE_PUT_LAMBDA_ARN))
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
        when(configService.getEnvironmentVariable(CI_STORAGE_GET_LAMBDA_ARN))
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
        when(configService.getEnvironmentVariable(CI_STORAGE_GET_LAMBDA_ARN))
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
        when(configService.getEnvironmentVariable(CI_STORAGE_GET_LAMBDA_ARN))
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
        when(configService.getEnvironmentVariable(CI_STORAGE_POST_MITIGATIONS_LAMBDA_ARN))
                .thenReturn(THE_ARN_OF_THE_POST_LAMBDA);
        when(lambdaClient.invoke(requestCaptor.capture()))
                .thenReturn(new InvokeResult().withStatusCode(200));

        ciStorageService.submitMitigatingVcList(
                List.of(SIGNED_VC_1), GOVUK_SIGNIN_JOURNEY_ID, CLIENT_SOURCE_IP);
        InvokeRequest request = requestCaptor.getValue();

        assertEquals(THE_ARN_OF_THE_POST_LAMBDA, request.getFunctionName());
        assertEquals(
                String.format(
                        "{\"govuk_signin_journey_id\":\"%s\",\"ip_address\":\"%s\",\"signed_jwts\":[\"%s\"]}",
                        GOVUK_SIGNIN_JOURNEY_ID, CLIENT_SOURCE_IP, SIGNED_VC_1),
                new String(request.getPayload().array(), StandardCharsets.UTF_8));
    }

    @Test
    void submitMitigationVCThrowsIfLambdaExecutionFails() {
        InvokeResult result = new InvokeResult().withStatusCode(500);
        when(configService.getEnvironmentVariable(CI_STORAGE_POST_MITIGATIONS_LAMBDA_ARN))
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
        when(configService.getEnvironmentVariable(CI_STORAGE_POST_MITIGATIONS_LAMBDA_ARN))
                .thenReturn(THE_ARN_OF_THE_POST_LAMBDA);
        when(lambdaClient.invoke(requestCaptor.capture())).thenReturn(result);

        assertThrows(
                CiPostMitigationsException.class,
                () ->
                        ciStorageService.submitMitigatingVcList(
                                List.of(SIGNED_VC_1), GOVUK_SIGNIN_JOURNEY_ID, CLIENT_SOURCE_IP));
    }

    @Test
    void getContraIndicatorCredentials() throws Exception {
        final ByteBuffer testLambdaResponse =
                ByteBuffer.wrap(
                        String.format("{\"signedJwt\":\"%s\"}", SIGNED_CONTRA_INDICATOR_VC)
                                .getBytes(StandardCharsets.UTF_8));
        when(configService.getEnvironmentVariable(CIMIT_GET_CONTRAINDICATORS_LAMBDA_ARN))
                .thenReturn(TEST_CIMIT_GET_CONTRAINDICATORS_LAMBDA_ARN);
        when(lambdaClient.invoke(requestCaptor.capture()))
                .thenReturn(new InvokeResult().withStatusCode(200).withPayload(testLambdaResponse));
        when(configService.getSsmParameter(ConfigurationVariable.CIMIT_COMPONENT_ID))
                .thenReturn("https://identity.staging.account.gov.uk");
        when(configService.getSsmParameter(ConfigurationVariable.CIMIT_SIGNING_KEY))
                .thenReturn(EC_PUBLIC_JWK);

        final ContraIndications contraIndications =
                ciStorageService.getContraIndicatorsVC(
                        TEST_USER_ID, GOVUK_SIGNIN_JOURNEY_ID, CLIENT_SOURCE_IP);
        final InvokeRequest request = requestCaptor.getValue();

        assertEquals(TEST_CIMIT_GET_CONTRAINDICATORS_LAMBDA_ARN, request.getFunctionName());
        assertEquals(
                String.format(
                        "{\"govuk_signin_journey_id\":\"%s\",\"ip_address\":\"%s\",\"user_id\":\"%s\"}",
                        GOVUK_SIGNIN_JOURNEY_ID, CLIENT_SOURCE_IP, TEST_USER_ID),
                new String(request.getPayload().array(), StandardCharsets.UTF_8));
        assertEquals(
                "ContraIndications(contraIndicatorMap={D01=ContraIndicator(contraIndicatorCode=D01, issuanceDate=2022-09-20T15:54:50Z, documentId=passport/GBR/824159121, transactionIds=[abcdef], mitigations=[Mitigation(mitigationCode=M01, mitigatingCredentials=[MitigatingCredential(issuer=https://credential-issuer.example/, validFrom=2022-09-21T15:54:50Z, transactionId=ghij, userId=urn:uuid:f81d4fae-7dec-11d0-a765-00a0c91e6bf6)])], incompleteMitigations=[Mitigation(mitigationCode=M02, mitigatingCredentials=[MitigatingCredential(issuer=https://another-credential-issuer.example/, validFrom=2022-09-22T15:54:50Z, transactionId=cdeef, userId=urn:uuid:f5c9ff40-1dcd-4a8b-bf92-9456047c132f)])])})",
                contraIndications.toString());
    }

    @Test
    void getContraIndicatorCredentialsThrowsErrorOnLambdaException() {
        when(configService.getEnvironmentVariable(CIMIT_GET_CONTRAINDICATORS_LAMBDA_ARN))
                .thenReturn(TEST_CIMIT_GET_CONTRAINDICATORS_LAMBDA_ARN);
        when(lambdaClient.invoke(any())).thenThrow(AWSLambdaException.class);

        assertThrows(
                CiRetrievalException.class,
                () ->
                        ciStorageService.getContraIndicatorsVC(
                                TEST_USER_ID, GOVUK_SIGNIN_JOURNEY_ID, CLIENT_SOURCE_IP));
    }

    @Test
    void getContraIndicatorCredentialsThrowsErrorOnLambdaFailure() {
        when(configService.getEnvironmentVariable(CIMIT_GET_CONTRAINDICATORS_LAMBDA_ARN))
                .thenReturn(TEST_CIMIT_GET_CONTRAINDICATORS_LAMBDA_ARN);
        when(lambdaClient.invoke(requestCaptor.capture()))
                .thenReturn(new InvokeResult().withStatusCode(403));

        assertThrows(
                CiRetrievalException.class,
                () ->
                        ciStorageService.getContraIndicatorsVC(
                                TEST_USER_ID, GOVUK_SIGNIN_JOURNEY_ID, CLIENT_SOURCE_IP));
    }

    @Test
    void getContraIndicatorCredentialsThrowsErrorOnInvalidJWT() {
        final ByteBuffer testLambdaResponse =
                ByteBuffer.wrap(
                        String.format("{\"signedJwt\":\"%s\"}", NOT_A_JWT)
                                .getBytes(StandardCharsets.UTF_8));
        when(configService.getEnvironmentVariable(CIMIT_GET_CONTRAINDICATORS_LAMBDA_ARN))
                .thenReturn(TEST_CIMIT_GET_CONTRAINDICATORS_LAMBDA_ARN);
        when(lambdaClient.invoke(any()))
                .thenReturn(new InvokeResult().withStatusCode(200).withPayload(testLambdaResponse));

        assertThrows(
                CiRetrievalException.class,
                () ->
                        ciStorageService.getContraIndicatorsVC(
                                TEST_USER_ID, GOVUK_SIGNIN_JOURNEY_ID, CLIENT_SOURCE_IP));
    }

    @Test
    void getContraIndicatorCredentialsThrowsErrorIfInvalidEvidence() {
        final ByteBuffer testLambdaResponse =
                ByteBuffer.wrap(
                        String.format(
                                        "{\"signedJwt\":\"%s\"}",
                                        SIGNED_CONTRA_INDICATOR_VC_INVALID_EVIDENCE)
                                .getBytes(StandardCharsets.UTF_8));
        when(configService.getEnvironmentVariable(CIMIT_GET_CONTRAINDICATORS_LAMBDA_ARN))
                .thenReturn(TEST_CIMIT_GET_CONTRAINDICATORS_LAMBDA_ARN);
        when(lambdaClient.invoke(any()))
                .thenReturn(new InvokeResult().withStatusCode(200).withPayload(testLambdaResponse));
        when(configService.getSsmParameter(ConfigurationVariable.CIMIT_COMPONENT_ID))
                .thenReturn("https://identity.staging.account.gov.uk");
        when(configService.getSsmParameter(ConfigurationVariable.CIMIT_SIGNING_KEY))
                .thenReturn(EC_PUBLIC_JWK);

        assertThrows(
                CiRetrievalException.class,
                () ->
                        ciStorageService.getContraIndicatorsVC(
                                TEST_USER_ID, GOVUK_SIGNIN_JOURNEY_ID, CLIENT_SOURCE_IP));
    }

    @Test
    void getContraIndicatorCredentialsThrowsErrorIfNoEvidence() {
        final ByteBuffer testLambdaResponse =
                ByteBuffer.wrap(
                        String.format(
                                        "{\"signedJwt\":\"%s\"}",
                                        SIGNED_CONTRA_INDICATOR_VC_NO_EVIDENCE)
                                .getBytes(StandardCharsets.UTF_8));
        when(configService.getEnvironmentVariable(CIMIT_GET_CONTRAINDICATORS_LAMBDA_ARN))
                .thenReturn(TEST_CIMIT_GET_CONTRAINDICATORS_LAMBDA_ARN);
        when(lambdaClient.invoke(any()))
                .thenReturn(new InvokeResult().withStatusCode(200).withPayload(testLambdaResponse));
        when(configService.getSsmParameter(ConfigurationVariable.CIMIT_COMPONENT_ID))
                .thenReturn("https://identity.staging.account.gov.uk");
        when(configService.getSsmParameter(ConfigurationVariable.CIMIT_SIGNING_KEY))
                .thenReturn(EC_PUBLIC_JWK);

        assertThrows(
                CiRetrievalException.class,
                () ->
                        ciStorageService.getContraIndicatorsVC(
                                TEST_USER_ID, GOVUK_SIGNIN_JOURNEY_ID, CLIENT_SOURCE_IP));
    }
}
