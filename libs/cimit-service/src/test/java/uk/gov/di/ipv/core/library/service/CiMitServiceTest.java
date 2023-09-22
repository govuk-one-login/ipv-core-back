package uk.gov.di.ipv.core.library.service;

import com.amazonaws.services.lambda.AWSLambda;
import com.amazonaws.services.lambda.model.AWSLambdaException;
import com.amazonaws.services.lambda.model.InvokeRequest;
import com.amazonaws.services.lambda.model.InvokeResult;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.cimit.dto.ContraIndicatorCredentialDto;
import uk.gov.di.ipv.core.library.cimit.exception.CiPostMitigationsException;
import uk.gov.di.ipv.core.library.cimit.exception.CiPutException;
import uk.gov.di.ipv.core.library.cimit.exception.CiRetrievalException;
import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
import uk.gov.di.ipv.core.library.cimit.domain.ContraIndicators;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.exceptions.VerifiableCredentialException;
import uk.gov.di.ipv.core.library.verifiablecredential.validator.VerifiableCredentialJwtValidator;

import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.config.EnvironmentVariable.CIMIT_GET_CONTRAINDICATORS_LAMBDA_ARN;
import static uk.gov.di.ipv.core.library.config.EnvironmentVariable.CI_STORAGE_POST_MITIGATIONS_LAMBDA_ARN;
import static uk.gov.di.ipv.core.library.config.EnvironmentVariable.CI_STORAGE_PUT_LAMBDA_ARN;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.EC_PUBLIC_JWK;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.SIGNED_CONTRA_INDICATOR_NO_VC;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.SIGNED_CONTRA_INDICATOR_VC;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.SIGNED_CONTRA_INDICATOR_VC_INVALID_EVIDENCE;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.SIGNED_CONTRA_INDICATOR_VC_NO_EVIDENCE;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.SIGNED_VC_1;

@ExtendWith(MockitoExtension.class)
class CiMitServiceTest {

    private static final String THE_ARN_OF_THE_PUT_LAMBDA = "the:arn:of:the:put:lambda";
    private static final String THE_ARN_OF_THE_POST_LAMBDA = "the:arn:of:the:post:lambda";
    private static final String THE_ARN_OF_CIMIT_GET_CI_LAMBDA = "arn:of:getContraIndicators";
    private static final String GOVUK_SIGNIN_JOURNEY_ID = "a-journey-id";
    private static final String TEST_USER_ID = "a-user-id";
    private static final String CLIENT_SOURCE_IP = "a-client-source-ip";
    private static final String CIMIT_COMPONENT_ID = "https://identity.staging.account.gov.uk";

    private static final ObjectMapper MAPPER = new ObjectMapper();
    @Captor ArgumentCaptor<InvokeRequest> requestCaptor;

    @Mock AWSLambda lambdaClient;
    @Mock ConfigService configService;
    @Mock VerifiableCredentialJwtValidator verifiableCredentialJwtValidator;
    @InjectMocks CiMitService ciMitService;

    @Test
    void submitVCInvokesTheLambdaClient() throws Exception {
        when(configService.getEnvironmentVariable(CI_STORAGE_PUT_LAMBDA_ARN))
                .thenReturn(THE_ARN_OF_THE_PUT_LAMBDA);
        when(lambdaClient.invoke(requestCaptor.capture()))
                .thenReturn(new InvokeResult().withStatusCode(200));

        ciMitService.submitVC(
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
                        ciMitService.submitVC(
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
                        ciMitService.submitVC(
                                SignedJWT.parse(SIGNED_VC_1),
                                GOVUK_SIGNIN_JOURNEY_ID,
                                CLIENT_SOURCE_IP));
    }

    @Test
    void submitMitigationVCInvokesTheLambdaClient() throws Exception {
        when(configService.getEnvironmentVariable(CI_STORAGE_POST_MITIGATIONS_LAMBDA_ARN))
                .thenReturn(THE_ARN_OF_THE_POST_LAMBDA);
        when(lambdaClient.invoke(requestCaptor.capture()))
                .thenReturn(new InvokeResult().withStatusCode(200));

        ciMitService.submitMitigatingVcList(
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
                        ciMitService.submitMitigatingVcList(
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
                        ciMitService.submitMitigatingVcList(
                                List.of(SIGNED_VC_1), GOVUK_SIGNIN_JOURNEY_ID, CLIENT_SOURCE_IP));
    }

    @Test
    void getContraIndicatorsVC() throws CiRetrievalException, JsonProcessingException {
        when(configService.getEnvironmentVariable(CIMIT_GET_CONTRAINDICATORS_LAMBDA_ARN))
                .thenReturn(THE_ARN_OF_CIMIT_GET_CI_LAMBDA);
        when(configService.getSsmParameter(ConfigurationVariable.CIMIT_COMPONENT_ID))
                .thenReturn(CIMIT_COMPONENT_ID);
        when(configService.getSsmParameter(ConfigurationVariable.CIMIT_SIGNING_KEY))
                .thenReturn(EC_PUBLIC_JWK);
        when(lambdaClient.invoke(requestCaptor.capture()))
                .thenReturn(
                        new InvokeResult()
                                .withStatusCode(200)
                                .withPayload(makeCiMitVCPayload(SIGNED_CONTRA_INDICATOR_VC)));

        ContraIndicators contraIndications =
                ciMitService.getContraIndicatorsVC(
                        TEST_USER_ID, GOVUK_SIGNIN_JOURNEY_ID, CLIENT_SOURCE_IP);

        verify(verifiableCredentialJwtValidator)
                .validateSignatureAndClaims(
                        any(SignedJWT.class),
                        any(ECKey.class),
                        eq(CIMIT_COMPONENT_ID),
                        eq(TEST_USER_ID));

        InvokeRequest request = requestCaptor.getValue();
        assertEquals(THE_ARN_OF_CIMIT_GET_CI_LAMBDA, request.getFunctionName());
        assertEquals(
                String.format(
                        "{\"govuk_signin_journey_id\":\"%s\",\"ip_address\":\"%s\",\"user_id\":\"%s\"}",
                        GOVUK_SIGNIN_JOURNEY_ID, CLIENT_SOURCE_IP, TEST_USER_ID),
                new String(request.getPayload().array(), StandardCharsets.UTF_8));

        assertEquals(
                "ContraIndicators(contraIndicatorsMap={D01=ContraIndicator(code=D01, issuanceDate=2022-09-20T15:54:50.000Z, document=passport/GBR/824159121, txn=[abcdef], mitigation=[Mitigation(code=M01, mitigatingCredential=[MitigatingCredential(issuer=https://credential-issuer.example/, validFrom=2022-09-21T15:54:50.000Z, txn=ghij, id=urn:uuid:f81d4fae-7dec-11d0-a765-00a0c91e6bf6)])], incompleteMitigation=[Mitigation(code=M02, mitigatingCredential=[MitigatingCredential(issuer=https://another-credential-issuer.example/, validFrom=2022-09-22T15:54:50.000Z, txn=cdeef, id=urn:uuid:f5c9ff40-1dcd-4a8b-bf92-9456047c132f)])])})",
                contraIndications.toString());
    }

    @Test
    void getContraIndicatorsVCThrowsExceptionIfLambdaExecutionFails() {
        InvokeResult result = new InvokeResult().withStatusCode(500);
        when(configService.getEnvironmentVariable(CIMIT_GET_CONTRAINDICATORS_LAMBDA_ARN))
                .thenReturn(THE_ARN_OF_CIMIT_GET_CI_LAMBDA);
        when(lambdaClient.invoke(requestCaptor.capture())).thenReturn(result);

        assertThrows(
                CiRetrievalException.class,
                () ->
                        ciMitService.getContraIndicatorsVC(
                                TEST_USER_ID, GOVUK_SIGNIN_JOURNEY_ID, CLIENT_SOURCE_IP));
    }

    @Test
    void getContraIndicatorsVCThrowsExceptionIfLambdaThrowsError() {
        InvokeResult result =
                new InvokeResult()
                        .withStatusCode(200)
                        .withFunctionError("Unhandled")
                        .withPayload(ByteBuffer.allocate(0));
        when(configService.getEnvironmentVariable(CIMIT_GET_CONTRAINDICATORS_LAMBDA_ARN))
                .thenReturn(THE_ARN_OF_CIMIT_GET_CI_LAMBDA);
        when(lambdaClient.invoke(requestCaptor.capture())).thenReturn(result);

        assertThrows(
                CiRetrievalException.class,
                () ->
                        ciMitService.getContraIndicatorsVC(
                                TEST_USER_ID, GOVUK_SIGNIN_JOURNEY_ID, CLIENT_SOURCE_IP));
    }

    @Test
    void getContraIndicatorVCThrowsErrorForInvalidJWT() throws JsonProcessingException {
        when(configService.getEnvironmentVariable(CIMIT_GET_CONTRAINDICATORS_LAMBDA_ARN))
                .thenReturn(THE_ARN_OF_CIMIT_GET_CI_LAMBDA);
        when(lambdaClient.invoke(any()))
                .thenReturn(
                        new InvokeResult()
                                .withStatusCode(200)
                                .withPayload(makeCiMitVCPayload("NOT_A_JWT")));

        assertThrows(
                CiRetrievalException.class,
                () ->
                        ciMitService.getContraIndicatorsVC(
                                TEST_USER_ID, GOVUK_SIGNIN_JOURNEY_ID, CLIENT_SOURCE_IP));
    }

    @Test
    void getContraIndicatorVCThrowsErrorForExceptionFromAWSLambdaClient() {
        when(configService.getEnvironmentVariable(CIMIT_GET_CONTRAINDICATORS_LAMBDA_ARN))
                .thenReturn(THE_ARN_OF_CIMIT_GET_CI_LAMBDA);
        doThrow(new AWSLambdaException("AWSLambda client invocation failed"))
                .when(lambdaClient)
                .invoke(any());

        assertThrows(
                CiRetrievalException.class,
                () ->
                        ciMitService.getContraIndicatorsVC(
                                TEST_USER_ID, GOVUK_SIGNIN_JOURNEY_ID, CLIENT_SOURCE_IP));
    }

    @Test
    void getContraIndicatorsVCThrowsExceptionIfVCValidationFails() throws JsonProcessingException {
        when(configService.getEnvironmentVariable(CIMIT_GET_CONTRAINDICATORS_LAMBDA_ARN))
                .thenReturn(THE_ARN_OF_CIMIT_GET_CI_LAMBDA);
        when(configService.getSsmParameter(ConfigurationVariable.CIMIT_COMPONENT_ID))
                .thenReturn(CIMIT_COMPONENT_ID);
        when(configService.getSsmParameter(ConfigurationVariable.CIMIT_SIGNING_KEY))
                .thenReturn(EC_PUBLIC_JWK);
        when(lambdaClient.invoke(requestCaptor.capture()))
                .thenReturn(
                        new InvokeResult()
                                .withStatusCode(200)
                                .withPayload(makeCiMitVCPayload(SIGNED_CONTRA_INDICATOR_VC)));
        doThrow(
                        new VerifiableCredentialException(
                                HTTPResponse.SC_SERVER_ERROR,
                                ErrorResponse.FAILED_TO_VALIDATE_VERIFIABLE_CREDENTIAL))
                .when(verifiableCredentialJwtValidator)
                .validateSignatureAndClaims(
                        any(SignedJWT.class),
                        any(ECKey.class),
                        eq(CIMIT_COMPONENT_ID),
                        eq(TEST_USER_ID));

        assertThrows(
                CiRetrievalException.class,
                () ->
                        ciMitService.getContraIndicatorsVC(
                                TEST_USER_ID, GOVUK_SIGNIN_JOURNEY_ID, CLIENT_SOURCE_IP));
    }

    @Test
    void getContraIndicatorCredentialsReturnEmptyCIIfInvalidEvidenceWithNoCI()
            throws CiRetrievalException, JsonProcessingException {
        when(configService.getEnvironmentVariable(CIMIT_GET_CONTRAINDICATORS_LAMBDA_ARN))
                .thenReturn(THE_ARN_OF_CIMIT_GET_CI_LAMBDA);
        when(configService.getSsmParameter(ConfigurationVariable.CIMIT_COMPONENT_ID))
                .thenReturn("https://identity.staging.account.gov.uk");
        when(configService.getSsmParameter(ConfigurationVariable.CIMIT_SIGNING_KEY))
                .thenReturn(EC_PUBLIC_JWK);
        when(lambdaClient.invoke(requestCaptor.capture()))
                .thenReturn(
                        new InvokeResult()
                                .withStatusCode(200)
                                .withPayload(
                                        makeCiMitVCPayload(
                                                SIGNED_CONTRA_INDICATOR_VC_INVALID_EVIDENCE)));

        ContraIndicators contraIndicators =
                ciMitService.getContraIndicatorsVC(
                        TEST_USER_ID, GOVUK_SIGNIN_JOURNEY_ID, CLIENT_SOURCE_IP);

        verify(verifiableCredentialJwtValidator)
                .validateSignatureAndClaims(
                        any(SignedJWT.class),
                        any(ECKey.class),
                        eq(CIMIT_COMPONENT_ID),
                        eq(TEST_USER_ID));

        InvokeRequest request = requestCaptor.getValue();
        assertEquals(THE_ARN_OF_CIMIT_GET_CI_LAMBDA, request.getFunctionName());
        assertEquals(
                String.format(
                        "{\"govuk_signin_journey_id\":\"%s\",\"ip_address\":\"%s\",\"user_id\":\"%s\"}",
                        GOVUK_SIGNIN_JOURNEY_ID, CLIENT_SOURCE_IP, TEST_USER_ID),
                new String(request.getPayload().array(), StandardCharsets.UTF_8));

        assertEquals("ContraIndicators(contraIndicatorsMap={})", contraIndicators.toString());
    }

    @Test
    void getContraIndicatorCredentialsThrowsErrorIfNoEvidence() throws JsonProcessingException {
        when(configService.getEnvironmentVariable(CIMIT_GET_CONTRAINDICATORS_LAMBDA_ARN))
                .thenReturn(THE_ARN_OF_CIMIT_GET_CI_LAMBDA);
        when(lambdaClient.invoke(any()))
                .thenReturn(
                        new InvokeResult()
                                .withStatusCode(200)
                                .withPayload(
                                        makeCiMitVCPayload(
                                                SIGNED_CONTRA_INDICATOR_VC_NO_EVIDENCE)));
        when(configService.getSsmParameter(ConfigurationVariable.CIMIT_COMPONENT_ID))
                .thenReturn("https://identity.staging.account.gov.uk");
        when(configService.getSsmParameter(ConfigurationVariable.CIMIT_SIGNING_KEY))
                .thenReturn(EC_PUBLIC_JWK);

        assertThrows(
                CiRetrievalException.class,
                () ->
                        ciMitService.getContraIndicatorsVC(
                                TEST_USER_ID, GOVUK_SIGNIN_JOURNEY_ID, CLIENT_SOURCE_IP));
    }

    @Test
    void getContraIndicatorsReturnsContraIndicatorsFromSignedJwt() throws Exception {
        SignedJWT.parse(SIGNED_CONTRA_INDICATOR_VC);
        ContraIndicators contraIndicators =
                ciMitService.getContraIndicators(SignedJWT.parse(SIGNED_CONTRA_INDICATOR_VC));

        assertTrue(contraIndicators.hasMitigations());
    }

    @Test
    void getContraIndicatorsVCJwtWhenValidJWT()
            throws CiRetrievalException, JsonProcessingException {
        when(configService.getEnvironmentVariable(CIMIT_GET_CONTRAINDICATORS_LAMBDA_ARN))
                .thenReturn(THE_ARN_OF_CIMIT_GET_CI_LAMBDA);
        when(configService.getSsmParameter(ConfigurationVariable.CIMIT_COMPONENT_ID))
                .thenReturn(CIMIT_COMPONENT_ID);
        when(configService.getSsmParameter(ConfigurationVariable.CIMIT_SIGNING_KEY))
                .thenReturn(EC_PUBLIC_JWK);
        when(lambdaClient.invoke(requestCaptor.capture()))
                .thenReturn(
                        new InvokeResult()
                                .withStatusCode(200)
                                .withPayload(makeCiMitVCPayload(SIGNED_CONTRA_INDICATOR_VC)));

        SignedJWT contraIndicatorsVCJwt =
                ciMitService.getContraIndicatorsVCJwt(
                        TEST_USER_ID, GOVUK_SIGNIN_JOURNEY_ID, CLIENT_SOURCE_IP);
        verify(verifiableCredentialJwtValidator)
                .validateSignatureAndClaims(
                        any(SignedJWT.class),
                        any(ECKey.class),
                        eq(CIMIT_COMPONENT_ID),
                        eq(TEST_USER_ID));

        InvokeRequest request = requestCaptor.getValue();
        assertEquals(THE_ARN_OF_CIMIT_GET_CI_LAMBDA, request.getFunctionName());
        assertEquals(
                String.format(
                        "{\"govuk_signin_journey_id\":\"%s\",\"ip_address\":\"%s\",\"user_id\":\"%s\"}",
                        GOVUK_SIGNIN_JOURNEY_ID, CLIENT_SOURCE_IP, TEST_USER_ID),
                new String(request.getPayload().array(), StandardCharsets.UTF_8));

        assertEquals(SIGNED_CONTRA_INDICATOR_VC, contraIndicatorsVCJwt.serialize());
    }

    @Test
    void getContraIndicatorsVCJwtWhenInvalidJWT() throws JsonProcessingException {
        when(configService.getEnvironmentVariable(CIMIT_GET_CONTRAINDICATORS_LAMBDA_ARN))
                .thenReturn(THE_ARN_OF_CIMIT_GET_CI_LAMBDA);
        when(lambdaClient.invoke(any()))
                .thenReturn(
                        new InvokeResult()
                                .withStatusCode(200)
                                .withPayload(makeCiMitVCPayload("NOT_A_JWT")));

        assertThrows(
                CiRetrievalException.class,
                () ->
                        ciMitService.getContraIndicatorsVCJwt(
                                TEST_USER_ID, GOVUK_SIGNIN_JOURNEY_ID, CLIENT_SOURCE_IP));
    }

    @Test
    void getContraIndicatorsVCJwtThrowsErrorWhenInvalidCimitKey() throws JsonProcessingException {
        when(configService.getEnvironmentVariable(CIMIT_GET_CONTRAINDICATORS_LAMBDA_ARN))
                .thenReturn(THE_ARN_OF_CIMIT_GET_CI_LAMBDA);
        when(configService.getSsmParameter(ConfigurationVariable.CIMIT_COMPONENT_ID))
                .thenReturn(CIMIT_COMPONENT_ID);
        when(configService.getSsmParameter(ConfigurationVariable.CIMIT_SIGNING_KEY))
                .thenReturn("INVALID_CIMIT_KEY");
        when(lambdaClient.invoke(any()))
                .thenReturn(
                        new InvokeResult()
                                .withStatusCode(200)
                                .withPayload(makeCiMitVCPayload(SIGNED_CONTRA_INDICATOR_VC)));

        assertThrows(
                CiRetrievalException.class,
                () ->
                        ciMitService.getContraIndicatorsVCJwt(
                                TEST_USER_ID, GOVUK_SIGNIN_JOURNEY_ID, CLIENT_SOURCE_IP));
    }

    @Test
    void getContraIndicatorsVCJwtThrowsErrorWhenNoVcBlock()
            throws CiRetrievalException, JsonProcessingException {
        when(configService.getEnvironmentVariable(CIMIT_GET_CONTRAINDICATORS_LAMBDA_ARN))
                .thenReturn(THE_ARN_OF_CIMIT_GET_CI_LAMBDA);
        when(configService.getSsmParameter(ConfigurationVariable.CIMIT_COMPONENT_ID))
                .thenReturn(CIMIT_COMPONENT_ID);
        when(configService.getSsmParameter(ConfigurationVariable.CIMIT_SIGNING_KEY))
                .thenReturn(EC_PUBLIC_JWK);
        when(lambdaClient.invoke(requestCaptor.capture()))
                .thenReturn(
                        new InvokeResult()
                                .withStatusCode(200)
                                .withPayload(makeCiMitVCPayload(SIGNED_CONTRA_INDICATOR_NO_VC)));

        assertThrows(
                CiRetrievalException.class,
                () ->
                        ciMitService.getContraIndicatorsVC(
                                TEST_USER_ID, GOVUK_SIGNIN_JOURNEY_ID, CLIENT_SOURCE_IP));
    }

    @Test
    void getContraIndicatorsVCJwtWhenAWSLambdaClientInvocationFailed() {
        when(configService.getEnvironmentVariable(CIMIT_GET_CONTRAINDICATORS_LAMBDA_ARN))
                .thenReturn(THE_ARN_OF_CIMIT_GET_CI_LAMBDA);
        doThrow(new AWSLambdaException("AWSLambda client invocation failed"))
                .when(lambdaClient)
                .invoke(any());

        assertThrows(
                CiRetrievalException.class,
                () ->
                        ciMitService.getContraIndicatorsVC(
                                TEST_USER_ID, GOVUK_SIGNIN_JOURNEY_ID, CLIENT_SOURCE_IP));
    }

    @Test
    void getContraIndicatorsVCJwtWhenVcValidationFails() throws JsonProcessingException {
        when(configService.getEnvironmentVariable(CIMIT_GET_CONTRAINDICATORS_LAMBDA_ARN))
                .thenReturn(THE_ARN_OF_CIMIT_GET_CI_LAMBDA);
        when(configService.getSsmParameter(ConfigurationVariable.CIMIT_COMPONENT_ID))
                .thenReturn(CIMIT_COMPONENT_ID);
        when(configService.getSsmParameter(ConfigurationVariable.CIMIT_SIGNING_KEY))
                .thenReturn(EC_PUBLIC_JWK);
        when(lambdaClient.invoke(requestCaptor.capture()))
                .thenReturn(
                        new InvokeResult()
                                .withStatusCode(200)
                                .withPayload(makeCiMitVCPayload(SIGNED_CONTRA_INDICATOR_VC)));
        doThrow(
                        new VerifiableCredentialException(
                                HTTPResponse.SC_SERVER_ERROR,
                                ErrorResponse.FAILED_TO_VALIDATE_VERIFIABLE_CREDENTIAL))
                .when(verifiableCredentialJwtValidator)
                .validateSignatureAndClaims(
                        any(SignedJWT.class),
                        any(ECKey.class),
                        eq(CIMIT_COMPONENT_ID),
                        eq(TEST_USER_ID));

        assertThrows(
                CiRetrievalException.class,
                () ->
                        ciMitService.getContraIndicatorsVCJwt(
                                TEST_USER_ID, GOVUK_SIGNIN_JOURNEY_ID, CLIENT_SOURCE_IP));
    }

    private ByteBuffer makeCiMitVCPayload(String signedJwt) throws JsonProcessingException {
        ContraIndicatorCredentialDto contraIndicatorCredentialDto =
                ContraIndicatorCredentialDto.builder().vc(signedJwt).build();
        return ByteBuffer.wrap(
                MAPPER.writerFor(ContraIndicatorCredentialDto.class)
                        .writeValueAsBytes(contraIndicatorCredentialDto));
    }
}
