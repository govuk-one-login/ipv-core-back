package uk.gov.di.ipv.core.library.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import org.apache.http.HttpStatus;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;
import software.amazon.awssdk.core.SdkBytes;
import software.amazon.awssdk.services.lambda.LambdaClient;
import software.amazon.awssdk.services.lambda.model.InvokeRequest;
import software.amazon.awssdk.services.lambda.model.InvokeResponse;
import software.amazon.awssdk.services.lambda.model.LambdaException;
import uk.gov.di.ipv.core.library.cimit.domain.PrivateApiResponse;
import uk.gov.di.ipv.core.library.cimit.dto.ContraIndicatorCredentialDto;
import uk.gov.di.ipv.core.library.cimit.exception.CiPostMitigationsException;
import uk.gov.di.ipv.core.library.cimit.exception.CiPutException;
import uk.gov.di.ipv.core.library.cimit.exception.CiRetrievalException;
import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
import uk.gov.di.ipv.core.library.domain.ContraIndicators;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.exceptions.CredentialParseException;
import uk.gov.di.ipv.core.library.exceptions.VerifiableCredentialException;
import uk.gov.di.ipv.core.library.verifiablecredential.validator.VerifiableCredentialValidator;

import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.http.HttpResponse.BodyHandler;
import java.text.ParseException;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.CALLS_REAL_METHODS;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.CIMIT_INTERNAL_API_KEY;
import static uk.gov.di.ipv.core.library.config.CoreFeatureFlag.CIMIT_API_GATEWAY_ENABLED;
import static uk.gov.di.ipv.core.library.config.EnvironmentVariable.CIMIT_GET_CONTRAINDICATORS_LAMBDA_ARN;
import static uk.gov.di.ipv.core.library.config.EnvironmentVariable.CI_STORAGE_POST_MITIGATIONS_LAMBDA_ARN;
import static uk.gov.di.ipv.core.library.config.EnvironmentVariable.CI_STORAGE_PUT_LAMBDA_ARN;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.SIGNED_CONTRA_INDICATOR_NO_VC;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.SIGNED_CONTRA_INDICATOR_VC;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.SIGNED_CONTRA_INDICATOR_VC_INVALID_EVIDENCE;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.SIGNED_CONTRA_INDICATOR_VC_NO_EVIDENCE;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.TEST_EC_PUBLIC_JWK;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.PASSPORT_NON_DCMAW_SUCCESSFUL_VC;
import static uk.gov.di.ipv.core.library.service.CiMitService.FAILED_RESPONSE;
import static uk.gov.di.ipv.core.library.service.CiMitService.IP_ADDRESS_HEADER;
import static uk.gov.di.ipv.core.library.service.CiMitService.X_API_KEY_HEADER;

@ExtendWith(MockitoExtension.class)
class CiMitServiceTest {
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final String THE_ARN_OF_THE_PUT_LAMBDA = "the:arn:of:the:put:lambda";
    private static final String THE_ARN_OF_THE_POST_LAMBDA = "the:arn:of:the:post:lambda";
    private static final String THE_ARN_OF_CIMIT_GET_CI_LAMBDA = "arn:of:getContraIndicators";
    private static final String GOVUK_SIGNIN_JOURNEY_ID = "a-journey-id";
    private static final String TEST_USER_ID = "a-user-id";
    private static final String CLIENT_SOURCE_IP = "a-client-source-ip";
    private static final String CIMIT_COMPONENT_ID = "https://identity.staging.account.gov.uk";
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final InvokeResponse INVOKE_RESPONSE_200 =
            InvokeResponse.builder().statusCode(200).build();
    private static final InvokeResponse INVOKE_RESPONSE_500 =
            InvokeResponse.builder().statusCode(500).build();
    private static final InvokeResponse INVOKE_RESPONSE_200_WITH_ERROR =
            InvokeResponse.builder()
                    .statusCode(200)
                    .functionError("Unhandled")
                    .payload(SdkBytes.fromUtf8String(""))
                    .build();
    private static final PrivateApiResponse SUCCESSFUL_POST_HTTP_RESPONSE =
            new PrivateApiResponse("success", null);
    private static final ContraIndicatorCredentialDto SUCCESSFUL_GET_CI_HTTP_RESPONSE =
            new ContraIndicatorCredentialDto(SIGNED_CONTRA_INDICATOR_VC);
    private static final PrivateApiResponse FAILED_CIMIT_HTTP_RESPONSE =
            new PrivateApiResponse(FAILED_RESPONSE, "Internal Server Error");
    private static final String CIMIT_API_BASE_URL = "https://base-url.co.uk";
    private static final String MOCK_CIMIT_API_KEY = "mock-api-key"; // pragma: allowlist secret

    @Captor private ArgumentCaptor<InvokeRequest> requestCaptor;
    @Mock private LambdaClient lambdaClient;
    @Mock private ConfigService configService;
    @Mock private VerifiableCredentialValidator verifiableCredentialValidator;
    @Mock private HttpClient mockHttpClient;
    @Mock private HttpResponse<String> mockHttpResponse;
    @Captor private ArgumentCaptor<HttpRequest> httpRequestCaptor;
    @Captor private ArgumentCaptor<String> stringCaptor;

    @InjectMocks CiMitService ciMitService;

    @Test
    void submitVCInvokesTheLambdaClient() throws Exception {
        var passportVc = PASSPORT_NON_DCMAW_SUCCESSFUL_VC;
        when(configService.getEnvironmentVariable(CI_STORAGE_PUT_LAMBDA_ARN))
                .thenReturn(THE_ARN_OF_THE_PUT_LAMBDA);
        when(lambdaClient.invoke(requestCaptor.capture())).thenReturn(INVOKE_RESPONSE_200);
        ciMitService.submitVC(passportVc, GOVUK_SIGNIN_JOURNEY_ID, CLIENT_SOURCE_IP);
        InvokeRequest request = requestCaptor.getValue();

        assertEquals(THE_ARN_OF_THE_PUT_LAMBDA, request.functionName());
        assertEquals(
                String.format(
                        "{\"govuk_signin_journey_id\":\"%s\",\"ip_address\":\"%s\",\"signed_jwt\":\"%s\"}",
                        GOVUK_SIGNIN_JOURNEY_ID, CLIENT_SOURCE_IP, passportVc.getVcString()),
                request.payload().asUtf8String());
    }

    @Test
    void submitVcSendsHttpRequestToApi() throws Exception {
        // Arrange
        when(configService.enabled(CIMIT_API_GATEWAY_ENABLED)).thenReturn(true);
        when(configService.getSsmParameter(ConfigurationVariable.CIMIT_INTERNAL_API_BASE_URL))
                .thenReturn(CIMIT_API_BASE_URL);
        when(configService.getAppApiKey(CIMIT_INTERNAL_API_KEY.getPath()))
                .thenReturn(MOCK_CIMIT_API_KEY);
        when(mockHttpClient.send(any(HttpRequest.class), any(BodyHandler.class)))
                .thenReturn(mockHttpResponse);
        when(mockHttpResponse.body())
                .thenReturn(OBJECT_MAPPER.writeValueAsString(SUCCESSFUL_POST_HTTP_RESPONSE));

        // Act
        try (MockedStatic<HttpRequest.BodyPublishers> mockedBodyPublishers =
                mockStatic(HttpRequest.BodyPublishers.class, CALLS_REAL_METHODS)) {
            ciMitService.submitVC(
                    PASSPORT_NON_DCMAW_SUCCESSFUL_VC, GOVUK_SIGNIN_JOURNEY_ID, CLIENT_SOURCE_IP);

            // Assert
            verify(mockHttpClient).send(httpRequestCaptor.capture(), any());
            HttpRequest httpRequest = httpRequestCaptor.getValue();
            assertEquals("POST", httpRequest.method());
            assertTrue(httpRequest.bodyPublisher().isPresent());
            assertTrue(httpRequest.headers().map().containsKey(X_API_KEY_HEADER));
            assertTrue(httpRequest.headers().map().containsKey(IP_ADDRESS_HEADER));
            assertTrue(
                    httpRequest
                            .headers()
                            .map()
                            .containsKey(CiMitService.GOVUK_SIGNIN_JOURNEY_ID_HEADER));

            mockedBodyPublishers.verify(
                    () -> HttpRequest.BodyPublishers.ofString(stringCaptor.capture()));
        }
    }

    @Test
    void submitVCThrowsIfHttpRequestReturnsFailResponse() throws Exception {
        // Arrange
        when(configService.enabled(CIMIT_API_GATEWAY_ENABLED)).thenReturn(true);
        when(configService.getSsmParameter(ConfigurationVariable.CIMIT_INTERNAL_API_BASE_URL))
                .thenReturn(CIMIT_API_BASE_URL);
        when(configService.getAppApiKey(CIMIT_INTERNAL_API_KEY.getPath()))
                .thenReturn(MOCK_CIMIT_API_KEY);
        when(mockHttpClient.send(any(HttpRequest.class), any(BodyHandler.class)))
                .thenReturn(mockHttpResponse);
        when(mockHttpResponse.body())
                .thenReturn(OBJECT_MAPPER.writeValueAsString(FAILED_CIMIT_HTTP_RESPONSE));

        // Act/Assert
        assertThrows(
                CiPutException.class,
                () ->
                        ciMitService.submitVC(
                                PASSPORT_NON_DCMAW_SUCCESSFUL_VC,
                                GOVUK_SIGNIN_JOURNEY_ID,
                                CLIENT_SOURCE_IP));
    }

    @Test
    void submitVCThrowsIfLambdaExecutionFails() {
        when(configService.getEnvironmentVariable(CI_STORAGE_PUT_LAMBDA_ARN))
                .thenReturn(THE_ARN_OF_THE_PUT_LAMBDA);
        when(lambdaClient.invoke(requestCaptor.capture())).thenReturn(INVOKE_RESPONSE_500);

        assertThrows(
                CiPutException.class,
                () ->
                        ciMitService.submitVC(
                                PASSPORT_NON_DCMAW_SUCCESSFUL_VC,
                                GOVUK_SIGNIN_JOURNEY_ID,
                                CLIENT_SOURCE_IP));
    }

    @Test
    void submitVCThrowsIfLambdaThrowsAnError() {
        when(configService.getEnvironmentVariable(CI_STORAGE_PUT_LAMBDA_ARN))
                .thenReturn(THE_ARN_OF_THE_PUT_LAMBDA);
        when(lambdaClient.invoke(requestCaptor.capture()))
                .thenReturn(INVOKE_RESPONSE_200_WITH_ERROR);
        assertThrows(
                CiPutException.class,
                () ->
                        ciMitService.submitVC(
                                PASSPORT_NON_DCMAW_SUCCESSFUL_VC,
                                GOVUK_SIGNIN_JOURNEY_ID,
                                CLIENT_SOURCE_IP));
    }

    @Test
    void submitMitigationVCInvokesTheLambdaClient() throws Exception {
        when(configService.getEnvironmentVariable(CI_STORAGE_POST_MITIGATIONS_LAMBDA_ARN))
                .thenReturn(THE_ARN_OF_THE_POST_LAMBDA);
        when(lambdaClient.invoke(requestCaptor.capture())).thenReturn(INVOKE_RESPONSE_200);

        var vcs = List.of(PASSPORT_NON_DCMAW_SUCCESSFUL_VC);
        ciMitService.submitMitigatingVcList(vcs, GOVUK_SIGNIN_JOURNEY_ID, CLIENT_SOURCE_IP);
        InvokeRequest request = requestCaptor.getValue();

        assertEquals(THE_ARN_OF_THE_POST_LAMBDA, request.functionName());
        assertEquals(
                String.format(
                        "{\"govuk_signin_journey_id\":\"%s\",\"ip_address\":\"%s\",\"signed_jwts\":[\"%s\"]}",
                        GOVUK_SIGNIN_JOURNEY_ID,
                        CLIENT_SOURCE_IP,
                        PASSPORT_NON_DCMAW_SUCCESSFUL_VC.getVcString()),
                request.payload().asUtf8String());
    }

    @Test
    void submitMitigationVCListSendsHttpRequestToApi() throws Exception {
        when(configService.enabled(CIMIT_API_GATEWAY_ENABLED)).thenReturn(true);
        when(configService.getSsmParameter(ConfigurationVariable.CIMIT_INTERNAL_API_BASE_URL))
                .thenReturn(CIMIT_API_BASE_URL);
        when(configService.getAppApiKey(CIMIT_INTERNAL_API_KEY.getPath()))
                .thenReturn(MOCK_CIMIT_API_KEY);
        when(mockHttpClient.send(any(HttpRequest.class), any(BodyHandler.class)))
                .thenReturn(mockHttpResponse);
        when(mockHttpResponse.body())
                .thenReturn(OBJECT_MAPPER.writeValueAsString(SUCCESSFUL_POST_HTTP_RESPONSE));

        var vcs = List.of(PASSPORT_NON_DCMAW_SUCCESSFUL_VC);
        // Act
        try (MockedStatic<HttpRequest.BodyPublishers> mockedBodyPublishers =
                mockStatic(HttpRequest.BodyPublishers.class, CALLS_REAL_METHODS)) {
            ciMitService.submitMitigatingVcList(vcs, GOVUK_SIGNIN_JOURNEY_ID, CLIENT_SOURCE_IP);

            // Assert
            verify(mockHttpClient).send(httpRequestCaptor.capture(), any());
            HttpRequest httpRequest = httpRequestCaptor.getValue();
            assertEquals("POST", httpRequest.method());
            assertTrue(httpRequest.bodyPublisher().isPresent());
            assertTrue(httpRequest.headers().map().containsKey(X_API_KEY_HEADER));
            assertTrue(httpRequest.headers().map().containsKey(IP_ADDRESS_HEADER));
            assertTrue(
                    httpRequest
                            .headers()
                            .map()
                            .containsKey(CiMitService.GOVUK_SIGNIN_JOURNEY_ID_HEADER));

            mockedBodyPublishers.verify(
                    () -> HttpRequest.BodyPublishers.ofString(stringCaptor.capture()));
        }
    }

    @Test
    void submitMitigationVCThrowsIfHttpRequestReturnsFailedResponse() throws Exception {
        // Arrange
        var vcs = List.of(PASSPORT_NON_DCMAW_SUCCESSFUL_VC);

        when(configService.enabled(CIMIT_API_GATEWAY_ENABLED)).thenReturn(true);
        when(configService.getSsmParameter(ConfigurationVariable.CIMIT_INTERNAL_API_BASE_URL))
                .thenReturn(CIMIT_API_BASE_URL);
        when(configService.getAppApiKey(CIMIT_INTERNAL_API_KEY.getPath()))
                .thenReturn(MOCK_CIMIT_API_KEY);
        when(mockHttpClient.send(any(HttpRequest.class), any(BodyHandler.class)))
                .thenReturn(mockHttpResponse);
        when(mockHttpResponse.body())
                .thenReturn(OBJECT_MAPPER.writeValueAsString(FAILED_CIMIT_HTTP_RESPONSE));

        // Act/Assert
        assertThrows(
                CiPostMitigationsException.class,
                () ->
                        ciMitService.submitMitigatingVcList(
                                vcs, GOVUK_SIGNIN_JOURNEY_ID, CLIENT_SOURCE_IP));
    }

    @Test
    void submitMitigationVCThrowsIfLambdaExecutionFails() {
        when(configService.getEnvironmentVariable(CI_STORAGE_POST_MITIGATIONS_LAMBDA_ARN))
                .thenReturn(THE_ARN_OF_THE_POST_LAMBDA);
        when(lambdaClient.invoke(requestCaptor.capture())).thenReturn(INVOKE_RESPONSE_500);

        var vcs = List.of(PASSPORT_NON_DCMAW_SUCCESSFUL_VC);
        assertThrows(
                CiPostMitigationsException.class,
                () ->
                        ciMitService.submitMitigatingVcList(
                                vcs, GOVUK_SIGNIN_JOURNEY_ID, CLIENT_SOURCE_IP));
    }

    @Test
    void submitMitigationVCThrowsIfLambdaThrowsAnError() {
        when(configService.getEnvironmentVariable(CI_STORAGE_POST_MITIGATIONS_LAMBDA_ARN))
                .thenReturn(THE_ARN_OF_THE_POST_LAMBDA);
        when(lambdaClient.invoke(requestCaptor.capture()))
                .thenReturn(INVOKE_RESPONSE_200_WITH_ERROR);

        var vcs = List.of(PASSPORT_NON_DCMAW_SUCCESSFUL_VC);
        assertThrows(
                CiPostMitigationsException.class,
                () ->
                        ciMitService.submitMitigatingVcList(
                                vcs, GOVUK_SIGNIN_JOURNEY_ID, CLIENT_SOURCE_IP));
    }

    @Test
    void getContraIndicatorsVC() throws Exception {
        when(configService.getEnvironmentVariable(CIMIT_GET_CONTRAINDICATORS_LAMBDA_ARN))
                .thenReturn(THE_ARN_OF_CIMIT_GET_CI_LAMBDA);
        when(configService.getParameter(ConfigurationVariable.CIMIT_COMPONENT_ID))
                .thenReturn(CIMIT_COMPONENT_ID);
        when(configService.getParameter(ConfigurationVariable.CIMIT_SIGNING_KEY))
                .thenReturn(TEST_EC_PUBLIC_JWK);
        when(verifiableCredentialValidator.parseAndValidate(
                        eq(TEST_USER_ID),
                        eq(null),
                        eq(SIGNED_CONTRA_INDICATOR_VC),
                        any(),
                        eq(CIMIT_COMPONENT_ID),
                        eq(false)))
                .thenReturn(
                        VerifiableCredential.fromValidJwt(
                                TEST_USER_ID, null, SignedJWT.parse(SIGNED_CONTRA_INDICATOR_VC)));
        when(lambdaClient.invoke(requestCaptor.capture()))
                .thenReturn(
                        InvokeResponse.builder()
                                .statusCode(200)
                                .payload(makeCiMitVCPayload(SIGNED_CONTRA_INDICATOR_VC))
                                .build());

        ContraIndicators contraIndications =
                ciMitService.getContraIndicators(
                        TEST_USER_ID, GOVUK_SIGNIN_JOURNEY_ID, CLIENT_SOURCE_IP);

        InvokeRequest request = requestCaptor.getValue();
        assertEquals(THE_ARN_OF_CIMIT_GET_CI_LAMBDA, request.functionName());
        assertEquals(
                String.format(
                        "{\"govuk_signin_journey_id\":\"%s\",\"ip_address\":\"%s\",\"user_id\":\"%s\"}",
                        GOVUK_SIGNIN_JOURNEY_ID, CLIENT_SOURCE_IP, TEST_USER_ID),
                request.payload().asUtf8String());

        assertEquals(
                "ContraIndicators(usersContraIndicators=[ContraIndicator(code=D01, issuers=[https://issuing-cri.example], issuanceDate=2022-09-20T15:54:50.000Z, document=passport/GBR/824159121, txn=[abcdef], mitigation=[Mitigation(code=M01, mitigatingCredential=[MitigatingCredential(issuer=https://credential-issuer.example/, validFrom=2022-09-21T15:54:50.000Z, txn=ghij, id=urn:uuid:f81d4fae-7dec-11d0-a765-00a0c91e6bf6)])], incompleteMitigation=[Mitigation(code=M02, mitigatingCredential=[MitigatingCredential(issuer=https://another-credential-issuer.example/, validFrom=2022-09-22T15:54:50.000Z, txn=cdeef, id=urn:uuid:f5c9ff40-1dcd-4a8b-bf92-9456047c132f)])])])",
                contraIndications.toString());
    }

    @Test
    void getContraIndicatorsSendsHttpRequestToCimitApi() throws Exception {
        // Arrange
        when(configService.enabled(CIMIT_API_GATEWAY_ENABLED)).thenReturn(true);
        when(configService.getSsmParameter(ConfigurationVariable.CIMIT_INTERNAL_API_BASE_URL))
                .thenReturn(CIMIT_API_BASE_URL);
        when(configService.getAppApiKey(CIMIT_INTERNAL_API_KEY.getPath()))
                .thenReturn(MOCK_CIMIT_API_KEY);
        when(mockHttpClient.send(any(HttpRequest.class), any(BodyHandler.class)))
                .thenReturn(mockHttpResponse);
        when(mockHttpResponse.statusCode()).thenReturn(HttpStatus.SC_OK);
        when(mockHttpResponse.body())
                .thenReturn(OBJECT_MAPPER.writeValueAsString(SUCCESSFUL_GET_CI_HTTP_RESPONSE));
        when(verifiableCredentialValidator.parseAndValidate(
                        eq(TEST_USER_ID),
                        eq(null),
                        eq(SIGNED_CONTRA_INDICATOR_VC),
                        any(),
                        eq(CIMIT_COMPONENT_ID),
                        eq(false)))
                .thenReturn(
                        VerifiableCredential.fromValidJwt(
                                TEST_USER_ID, null, SignedJWT.parse(SIGNED_CONTRA_INDICATOR_VC)));
        when(configService.getSsmParameter(ConfigurationVariable.CIMIT_COMPONENT_ID))
                .thenReturn(CIMIT_COMPONENT_ID);
        when(configService.getSsmParameter(ConfigurationVariable.CIMIT_SIGNING_KEY))
                .thenReturn(TEST_EC_PUBLIC_JWK);

        // Act
        var cis =
                ciMitService.getContraIndicators(
                        TEST_USER_ID, GOVUK_SIGNIN_JOURNEY_ID, CLIENT_SOURCE_IP);

        // Assert
        verify(mockHttpClient).send(httpRequestCaptor.capture(), any());
        HttpRequest httpRequest = httpRequestCaptor.getValue();
        assertEquals("GET", httpRequest.method());
        assertTrue(httpRequest.headers().map().containsKey(X_API_KEY_HEADER));
        assertTrue(httpRequest.headers().map().containsKey(IP_ADDRESS_HEADER));
        assertTrue(
                httpRequest
                        .headers()
                        .map()
                        .containsKey(CiMitService.GOVUK_SIGNIN_JOURNEY_ID_HEADER));
        assertEquals(
                "ContraIndicators(usersContraIndicators=[ContraIndicator(code=D01, issuers=[https://issuing-cri.example], issuanceDate=2022-09-20T15:54:50.000Z, document=passport/GBR/824159121, txn=[abcdef], mitigation=[Mitigation(code=M01, mitigatingCredential=[MitigatingCredential(issuer=https://credential-issuer.example/, validFrom=2022-09-21T15:54:50.000Z, txn=ghij, id=urn:uuid:f81d4fae-7dec-11d0-a765-00a0c91e6bf6)])], incompleteMitigation=[Mitigation(code=M02, mitigatingCredential=[MitigatingCredential(issuer=https://another-credential-issuer.example/, validFrom=2022-09-22T15:54:50.000Z, txn=cdeef, id=urn:uuid:f5c9ff40-1dcd-4a8b-bf92-9456047c132f)])])])",
                cis.toString());
    }

    @Test
    void getContraIndicatorsVCThrowsExceptionIfHttpRequestReturnsFailedResponse() throws Exception {
        // Arrange
        when(configService.enabled(CIMIT_API_GATEWAY_ENABLED)).thenReturn(true);
        when(configService.getSsmParameter(ConfigurationVariable.CIMIT_INTERNAL_API_BASE_URL))
                .thenReturn(CIMIT_API_BASE_URL);
        when(configService.getAppApiKey(CIMIT_INTERNAL_API_KEY.getPath()))
                .thenReturn(MOCK_CIMIT_API_KEY);
        when(mockHttpClient.send(any(HttpRequest.class), any(BodyHandler.class)))
                .thenReturn(mockHttpResponse);
        when(mockHttpResponse.statusCode()).thenReturn(HttpStatus.SC_INTERNAL_SERVER_ERROR);
        when(mockHttpResponse.body())
                .thenReturn(OBJECT_MAPPER.writeValueAsString(FAILED_CIMIT_HTTP_RESPONSE));

        // Act/Assert
        assertThrows(
                CiRetrievalException.class,
                () ->
                        ciMitService.getContraIndicators(
                                TEST_USER_ID, GOVUK_SIGNIN_JOURNEY_ID, CLIENT_SOURCE_IP));
    }

    @Test
    void getContraIndicatorsVCThrowsExceptionIfLambdaExecutionFails() {
        when(configService.getEnvironmentVariable(CIMIT_GET_CONTRAINDICATORS_LAMBDA_ARN))
                .thenReturn(THE_ARN_OF_CIMIT_GET_CI_LAMBDA);
        when(lambdaClient.invoke(requestCaptor.capture())).thenReturn(INVOKE_RESPONSE_500);

        assertThrows(
                CiRetrievalException.class,
                () ->
                        ciMitService.getContraIndicators(
                                TEST_USER_ID, GOVUK_SIGNIN_JOURNEY_ID, CLIENT_SOURCE_IP));
    }

    @Test
    void getContraIndicatorsVCThrowsExceptionIfLambdaThrowsError() {
        when(configService.getEnvironmentVariable(CIMIT_GET_CONTRAINDICATORS_LAMBDA_ARN))
                .thenReturn(THE_ARN_OF_CIMIT_GET_CI_LAMBDA);
        when(lambdaClient.invoke(requestCaptor.capture()))
                .thenReturn(INVOKE_RESPONSE_200_WITH_ERROR);

        assertThrows(
                CiRetrievalException.class,
                () ->
                        ciMitService.getContraIndicators(
                                TEST_USER_ID, GOVUK_SIGNIN_JOURNEY_ID, CLIENT_SOURCE_IP));
    }

    @Test
    void getContraIndicatorVCThrowsErrorForInvalidJWT() throws Exception {
        when(configService.getEnvironmentVariable(CIMIT_GET_CONTRAINDICATORS_LAMBDA_ARN))
                .thenReturn(THE_ARN_OF_CIMIT_GET_CI_LAMBDA);
        when(configService.getParameter(ConfigurationVariable.CIMIT_COMPONENT_ID))
                .thenReturn(CIMIT_COMPONENT_ID);
        when(configService.getParameter(ConfigurationVariable.CIMIT_SIGNING_KEY))
                .thenReturn(TEST_EC_PUBLIC_JWK);
        when(verifiableCredentialValidator.parseAndValidate(
                        any(), any(), any(), any(), any(), eq(false)))
                .thenThrow(
                        new VerifiableCredentialException(
                                500, ErrorResponse.FAILED_TO_VALIDATE_VERIFIABLE_CREDENTIAL));
        when(lambdaClient.invoke(any(InvokeRequest.class)))
                .thenReturn(
                        InvokeResponse.builder()
                                .statusCode(200)
                                .payload(makeCiMitVCPayload("NOT_A_JWT"))
                                .build());

        assertThrows(
                CiRetrievalException.class,
                () ->
                        ciMitService.getContraIndicators(
                                TEST_USER_ID, GOVUK_SIGNIN_JOURNEY_ID, CLIENT_SOURCE_IP));
    }

    @Test
    void getContraIndicatorVCThrowsErrorForExceptionFromAWSLambdaClient() {
        when(configService.getEnvironmentVariable(CIMIT_GET_CONTRAINDICATORS_LAMBDA_ARN))
                .thenReturn(THE_ARN_OF_CIMIT_GET_CI_LAMBDA);
        doThrow(LambdaException.builder().message("AWSLambda client invocation failed").build())
                .when(lambdaClient)
                .invoke(any(InvokeRequest.class));

        assertThrows(
                CiRetrievalException.class,
                () ->
                        ciMitService.getContraIndicators(
                                TEST_USER_ID, GOVUK_SIGNIN_JOURNEY_ID, CLIENT_SOURCE_IP));
    }

    @Test
    void getContraIndicatorsVCThrowsExceptionIfVCValidationFails() throws Exception {
        when(configService.getEnvironmentVariable(CIMIT_GET_CONTRAINDICATORS_LAMBDA_ARN))
                .thenReturn(THE_ARN_OF_CIMIT_GET_CI_LAMBDA);
        when(configService.getParameter(ConfigurationVariable.CIMIT_COMPONENT_ID))
                .thenReturn(CIMIT_COMPONENT_ID);
        when(configService.getParameter(ConfigurationVariable.CIMIT_SIGNING_KEY))
                .thenReturn(TEST_EC_PUBLIC_JWK);
        when(lambdaClient.invoke(requestCaptor.capture()))
                .thenReturn(
                        InvokeResponse.builder()
                                .statusCode(200)
                                .payload(makeCiMitVCPayload(SIGNED_CONTRA_INDICATOR_VC))
                                .build());
        doThrow(
                        new VerifiableCredentialException(
                                HTTPResponse.SC_SERVER_ERROR,
                                ErrorResponse.FAILED_TO_VALIDATE_VERIFIABLE_CREDENTIAL))
                .when(verifiableCredentialValidator)
                .parseAndValidate(any(), any(), any(), any(), any(), anyBoolean());

        assertThrows(
                CiRetrievalException.class,
                () ->
                        ciMitService.getContraIndicators(
                                TEST_USER_ID, GOVUK_SIGNIN_JOURNEY_ID, CLIENT_SOURCE_IP));
    }

    @Test
    void getContraIndicatorCredentialsReturnEmptyCIIfInvalidEvidenceWithNoCI() throws Exception {
        when(configService.getEnvironmentVariable(CIMIT_GET_CONTRAINDICATORS_LAMBDA_ARN))
                .thenReturn(THE_ARN_OF_CIMIT_GET_CI_LAMBDA);
        when(configService.getParameter(ConfigurationVariable.CIMIT_COMPONENT_ID))
                .thenReturn("https://identity.staging.account.gov.uk");
        when(configService.getParameter(ConfigurationVariable.CIMIT_SIGNING_KEY))
                .thenReturn(TEST_EC_PUBLIC_JWK);
        when(verifiableCredentialValidator.parseAndValidate(
                        any(), any(), any(), any(), any(), anyBoolean()))
                .thenReturn(
                        VerifiableCredential.fromValidJwt(
                                TEST_USER_ID,
                                null,
                                SignedJWT.parse(SIGNED_CONTRA_INDICATOR_VC_INVALID_EVIDENCE)));
        when(lambdaClient.invoke(requestCaptor.capture()))
                .thenReturn(
                        InvokeResponse.builder()
                                .statusCode(200)
                                .payload(
                                        makeCiMitVCPayload(
                                                SIGNED_CONTRA_INDICATOR_VC_INVALID_EVIDENCE))
                                .build());

        ContraIndicators contraIndicators =
                ciMitService.getContraIndicators(
                        TEST_USER_ID, GOVUK_SIGNIN_JOURNEY_ID, CLIENT_SOURCE_IP);

        InvokeRequest request = requestCaptor.getValue();
        assertEquals(THE_ARN_OF_CIMIT_GET_CI_LAMBDA, request.functionName());
        assertEquals(
                String.format(
                        "{\"govuk_signin_journey_id\":\"%s\",\"ip_address\":\"%s\",\"user_id\":\"%s\"}",
                        GOVUK_SIGNIN_JOURNEY_ID, CLIENT_SOURCE_IP, TEST_USER_ID),
                request.payload().asUtf8String());

        assertEquals("ContraIndicators(usersContraIndicators=[])", contraIndicators.toString());
    }

    @Test
    void getContraIndicatorCredentialsThrowsErrorIfNoEvidence()
            throws JsonProcessingException, VerifiableCredentialException, ParseException,
                    CredentialParseException {
        when(configService.getEnvironmentVariable(CIMIT_GET_CONTRAINDICATORS_LAMBDA_ARN))
                .thenReturn(THE_ARN_OF_CIMIT_GET_CI_LAMBDA);
        when(lambdaClient.invoke(any(InvokeRequest.class)))
                .thenReturn(
                        InvokeResponse.builder()
                                .statusCode(200)
                                .payload(makeCiMitVCPayload(SIGNED_CONTRA_INDICATOR_VC_NO_EVIDENCE))
                                .build());
        when(configService.getParameter(ConfigurationVariable.CIMIT_COMPONENT_ID))
                .thenReturn("https://identity.staging.account.gov.uk");
        when(configService.getParameter(ConfigurationVariable.CIMIT_SIGNING_KEY))
                .thenReturn(TEST_EC_PUBLIC_JWK);
        when(verifiableCredentialValidator.parseAndValidate(
                        any(), any(), any(), any(), any(), anyBoolean()))
                .thenReturn(
                        VerifiableCredential.fromValidJwt(
                                TEST_USER_ID,
                                null,
                                SignedJWT.parse(SIGNED_CONTRA_INDICATOR_VC_NO_EVIDENCE)));

        assertThrows(
                CiRetrievalException.class,
                () ->
                        ciMitService.getContraIndicators(
                                TEST_USER_ID, GOVUK_SIGNIN_JOURNEY_ID, CLIENT_SOURCE_IP));
    }

    @Test
    void getContraIndicatorsReturnsContraIndicatorsFromSignedJwt() throws Exception {
        var vc =
                VerifiableCredential.fromValidJwt(
                        TEST_USER_ID, null, SignedJWT.parse(SIGNED_CONTRA_INDICATOR_VC));
        ContraIndicators contraIndicators = ciMitService.getContraIndicators(vc);

        assertTrue(contraIndicators.hasMitigations());
    }

    @Test
    void getContraIndicatorsVCJwtWhenValidJWT() throws Exception {
        when(configService.getEnvironmentVariable(CIMIT_GET_CONTRAINDICATORS_LAMBDA_ARN))
                .thenReturn(THE_ARN_OF_CIMIT_GET_CI_LAMBDA);
        when(configService.getParameter(ConfigurationVariable.CIMIT_COMPONENT_ID))
                .thenReturn(CIMIT_COMPONENT_ID);
        when(configService.getParameter(ConfigurationVariable.CIMIT_SIGNING_KEY))
                .thenReturn(TEST_EC_PUBLIC_JWK);
        when(verifiableCredentialValidator.parseAndValidate(
                        eq(TEST_USER_ID),
                        eq(null),
                        eq(SIGNED_CONTRA_INDICATOR_VC),
                        any(),
                        eq(CIMIT_COMPONENT_ID),
                        eq(false)))
                .thenReturn(
                        VerifiableCredential.fromValidJwt(
                                TEST_USER_ID, null, SignedJWT.parse(SIGNED_CONTRA_INDICATOR_VC)));
        when(lambdaClient.invoke(requestCaptor.capture()))
                .thenReturn(
                        InvokeResponse.builder()
                                .statusCode(200)
                                .payload(makeCiMitVCPayload(SIGNED_CONTRA_INDICATOR_VC))
                                .build());

        VerifiableCredential contraIndicatorsVc =
                ciMitService.getContraIndicatorsVc(
                        TEST_USER_ID, GOVUK_SIGNIN_JOURNEY_ID, CLIENT_SOURCE_IP);

        InvokeRequest request = requestCaptor.getValue();
        assertEquals(THE_ARN_OF_CIMIT_GET_CI_LAMBDA, request.functionName());
        assertEquals(
                String.format(
                        "{\"govuk_signin_journey_id\":\"%s\",\"ip_address\":\"%s\",\"user_id\":\"%s\"}",
                        GOVUK_SIGNIN_JOURNEY_ID, CLIENT_SOURCE_IP, TEST_USER_ID),
                request.payload().asUtf8String());

        assertEquals(SIGNED_CONTRA_INDICATOR_VC, contraIndicatorsVc.getVcString());
    }

    @Test
    void getContraIndicatorsVCJwtThrowsErrorWhenInvalidCimitKey()
            throws JsonProcessingException, VerifiableCredentialException {
        when(configService.getEnvironmentVariable(CIMIT_GET_CONTRAINDICATORS_LAMBDA_ARN))
                .thenReturn(THE_ARN_OF_CIMIT_GET_CI_LAMBDA);
        when(configService.getParameter(ConfigurationVariable.CIMIT_COMPONENT_ID))
                .thenReturn(CIMIT_COMPONENT_ID);
        when(configService.getParameter(ConfigurationVariable.CIMIT_SIGNING_KEY))
                .thenReturn("INVALID_CIMIT_KEY");
        when(lambdaClient.invoke(any(InvokeRequest.class)))
                .thenReturn(
                        InvokeResponse.builder()
                                .statusCode(200)
                                .payload(makeCiMitVCPayload(SIGNED_CONTRA_INDICATOR_VC))
                                .build());
        when(verifiableCredentialValidator.parseAndValidate(
                        TEST_USER_ID,
                        null,
                        SIGNED_CONTRA_INDICATOR_VC,
                        "INVALID_CIMIT_KEY",
                        CIMIT_COMPONENT_ID,
                        false))
                .thenThrow(
                        new VerifiableCredentialException(
                                HTTPResponse.SC_SERVER_ERROR,
                                ErrorResponse.FAILED_TO_VALIDATE_VERIFIABLE_CREDENTIAL));

        assertThrows(
                CiRetrievalException.class,
                () ->
                        ciMitService.getContraIndicatorsVc(
                                TEST_USER_ID, GOVUK_SIGNIN_JOURNEY_ID, CLIENT_SOURCE_IP));
    }

    @Test
    void getContraIndicatorsVCJwtWhenVcValidationFails() throws Exception {
        when(configService.getEnvironmentVariable(CIMIT_GET_CONTRAINDICATORS_LAMBDA_ARN))
                .thenReturn(THE_ARN_OF_CIMIT_GET_CI_LAMBDA);
        when(configService.getParameter(ConfigurationVariable.CIMIT_COMPONENT_ID))
                .thenReturn(CIMIT_COMPONENT_ID);
        when(configService.getParameter(ConfigurationVariable.CIMIT_SIGNING_KEY))
                .thenReturn(TEST_EC_PUBLIC_JWK);
        when(lambdaClient.invoke(requestCaptor.capture()))
                .thenReturn(
                        InvokeResponse.builder()
                                .statusCode(200)
                                .payload(makeCiMitVCPayload(SIGNED_CONTRA_INDICATOR_NO_VC))
                                .build());
        doThrow(
                        new VerifiableCredentialException(
                                HTTPResponse.SC_SERVER_ERROR,
                                ErrorResponse.FAILED_TO_VALIDATE_VERIFIABLE_CREDENTIAL))
                .when(verifiableCredentialValidator)
                .parseAndValidate(any(), any(), any(), any(), any(), anyBoolean());

        assertThrows(
                CiRetrievalException.class,
                () ->
                        ciMitService.getContraIndicatorsVc(
                                TEST_USER_ID, GOVUK_SIGNIN_JOURNEY_ID, CLIENT_SOURCE_IP));
    }

    private SdkBytes makeCiMitVCPayload(String signedJwt) throws JsonProcessingException {
        ContraIndicatorCredentialDto contraIndicatorCredentialDto =
                ContraIndicatorCredentialDto.builder().vc(signedJwt).build();
        return SdkBytes.fromByteArray(
                MAPPER.writerFor(ContraIndicatorCredentialDto.class)
                        .writeValueAsBytes(contraIndicatorCredentialDto));
    }
}
