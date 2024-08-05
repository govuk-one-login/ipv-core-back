package uk.gov.di.ipv.core.library.pact;

import au.com.dius.pact.consumer.MockServer;
import au.com.dius.pact.consumer.dsl.PactDslRequestBase;
import au.com.dius.pact.consumer.dsl.PactDslWithProvider;
import au.com.dius.pact.consumer.junit.MockServerConfig;
import au.com.dius.pact.consumer.junit5.PactConsumerTestExt;
import au.com.dius.pact.consumer.junit5.PactTestFor;
import au.com.dius.pact.core.model.RequestResponsePact;
import au.com.dius.pact.core.model.annotations.Pact;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.cimit.exception.CiPostMitigationsException;
import uk.gov.di.ipv.core.library.cimit.exception.CiPutException;
import uk.gov.di.ipv.core.library.cimit.exception.CiRetrievalException;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.exceptions.CredentialParseException;
import uk.gov.di.ipv.core.library.pacttesthelpers.PactJwtBuilder;
import uk.gov.di.ipv.core.library.service.CiMitService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.model.SecurityCheck;
import uk.gov.di.model.SecurityCheckCredential;

import java.net.http.HttpRequest;
import java.text.ParseException;
import java.util.List;

import static au.com.dius.pact.consumer.dsl.LambdaDsl.newJsonBody;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.CIMIT_API_BASE_URL;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.CIMIT_API_KEY;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.CIMIT_COMPONENT_ID;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.CIMIT_SIGNING_KEY;
import static uk.gov.di.ipv.core.library.config.CoreFeatureFlag.CIMIT_API_GATEWAY_ENABLED;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.EC_PRIVATE_KEY_JWK;
import static uk.gov.di.ipv.core.library.service.CiMitService.FAILED_API_REQUEST;
import static uk.gov.di.ipv.core.library.service.CiMitService.GET_VCS_ENDPOINT;
import static uk.gov.di.ipv.core.library.service.CiMitService.GOVUK_SIGNIN_JOURNEY_ID_HEADER;
import static uk.gov.di.ipv.core.library.service.CiMitService.IP_ADDRESS_HEADER;
import static uk.gov.di.ipv.core.library.service.CiMitService.POST_CI_ENDPOINT;
import static uk.gov.di.ipv.core.library.service.CiMitService.POST_MITIGATIONS_ENDPOINT;
import static uk.gov.di.ipv.core.library.service.CiMitService.X_API_KEY_HEADER;

@ExtendWith(PactConsumerTestExt.class)
@ExtendWith(MockitoExtension.class)
@PactTestFor(providerName = "CiMitProvider")
@MockServerConfig(hostInterface = "localhost")
public class ContractTest {
    @Mock ConfigService mockConfigService;
    @Captor private ArgumentCaptor<HttpRequest> httpRequestCaptor;

    @BeforeEach
    void setUp() {
        when(mockConfigService.enabled(CIMIT_API_GATEWAY_ENABLED)).thenReturn(true);
        when(mockConfigService.getSecret(CIMIT_API_KEY)).thenReturn(MOCK_API_KEY);
    }

    @Pact(provider = "CiMitProvider", consumer = "IpvCoreBack")
    public RequestResponsePact validUserIdReturnsContraIndicators(PactDslWithProvider builder) {
        var responseForGetCi =
                newJsonBody(
                                body -> {
                                    var jwtBuilder =
                                            new PactJwtBuilder(
                                                    VALID_VC_HEADER,
                                                    VALID_CI_VC_BODY,
                                                    VALID_CI_VC_SIGNATURE);

                                    body.stringValue("vc", jwtBuilder.buildJwt());
                                })
                        .build();

        // TODO: these statements need to be updated to more accurately reflect the test data (test
        // data must be confirmed with ticf team)
        return builder.given("mockApiKey is a valid api key")
                .given("mockUserId is the user_id")
                .given("the current time is 2024-01-01 00:00:00")
                .given("mockCimitComponentId is the issuer")
                .given("there is one contra-indicator with an incomplete mitigation")
                .uponReceiving(
                        "Request for contra-indicators for specific user with existing contra-indicators.")
                .path(GET_VCS_ENDPOINT)
                .query("user_id=" + MOCK_USER_ID)
                .method("GET")
                .headers(
                        X_API_KEY_HEADER,
                        MOCK_API_KEY,
                        IP_ADDRESS_HEADER,
                        MOCK_IP_ADDRESS,
                        GOVUK_SIGNIN_JOURNEY_ID_HEADER,
                        MOCK_GOVUK_SIGNIN_ID,
                        PactDslRequestBase.CONTENT_TYPE,
                        "application/json")
                .willRespondWith()
                .status(200)
                .body(responseForGetCi)
                .toPact();
    }

    @Test
    @PactTestFor(pactMethod = "validUserIdReturnsContraIndicators")
    void fetchContraIndicators_whenCalledWithValidUserIdAgainstCimiApi_receivesContraIndicators(
            MockServer mockServer) throws CiRetrievalException {
        // Arrange
        when(mockConfigService.getParameter(CIMIT_COMPONENT_ID)).thenReturn(TEST_ISSUER);
        when(mockConfigService.getParameter(CIMIT_SIGNING_KEY)).thenReturn(EC_PRIVATE_KEY_JWK);
        when(mockConfigService.getParameter(CIMIT_API_BASE_URL))
                .thenReturn(getMockApiBaseUrl(mockServer));
        var underTest = new CiMitService(mockConfigService);

        // Act
        var contraIndicator =
                underTest.getContraIndicatorsVc(
                        MOCK_USER_ID, MOCK_GOVUK_SIGNIN_ID, MOCK_IP_ADDRESS);

        // Assert
        assertEquals(contraIndicator.getUserId(), MOCK_USER_ID);
        assertInstanceOf(SecurityCheckCredential.class, contraIndicator.getCredential());

        var securityCheckCredential = (SecurityCheckCredential) contraIndicator.getCredential();
        var evidence = (SecurityCheck) securityCheckCredential.getEvidence().get(0);
        assertEquals(evidence.getContraIndicator().size(), 1);
    }

    @Pact(provider = "CiMitProvider", consumer = "IpvCoreBack")
    public RequestResponsePact failsToReceiveContraIndicatorsDueToInternalServerError(
            PactDslWithProvider builder) {
        var responseForGetCi =
                newJsonBody(
                                body -> {
                                    body.stringValue("result", "fail");
                                    body.stringValue("reason", "INTERNAL_ERROR");
                                })
                        .build();

        // TODO: these statements need to be updated to more accurately reflect the test data (test
        // data must be confirmed with ticf team)
        return builder.given("mockApiKey is a valid api key")
                .given("mockUserId is the user_id")
                .given("the current time is 2024-01-01 00:00:00")
                .given("mockCimitComponentId is the issuer")
                .given("there is one contra-indicator with an incomplete mitigation")
                .uponReceiving(
                        "Request for contra-indicators for specific user with existing contra-indicators.")
                .path(GET_VCS_ENDPOINT)
                .query("user_id=" + MOCK_USER_ID)
                .method("GET")
                .headers(
                        X_API_KEY_HEADER,
                        MOCK_API_KEY,
                        IP_ADDRESS_HEADER,
                        MOCK_IP_ADDRESS,
                        GOVUK_SIGNIN_JOURNEY_ID_HEADER,
                        MOCK_GOVUK_SIGNIN_ID,
                        PactDslRequestBase.CONTENT_TYPE,
                        "application/json")
                .willRespondWith()
                .status(500)
                .body(responseForGetCi)
                .toPact();
    }

    @Test
    @PactTestFor(pactMethod = "failsToReceiveContraIndicatorsDueToInternalServerError")
    void fetchContraIndicators_whenCalledAgainstCimiApi_failsToReturnContraIndicators(
            MockServer mockServer) {
        // Arrange
        when(mockConfigService.getParameter(CIMIT_API_BASE_URL))
                .thenReturn(getMockApiBaseUrl(mockServer));
        var underTest = new CiMitService(mockConfigService);

        // Act/Assert
        assertThrows(
                CiRetrievalException.class,
                () ->
                        underTest.getContraIndicators(
                                MOCK_USER_ID, MOCK_GOVUK_SIGNIN_ID, MOCK_IP_ADDRESS),
                FAILED_API_REQUEST);
    }

    @Pact(provider = "CiMitProvider", consumer = "IpvCoreBack")
    public RequestResponsePact successfullyPostsContraIndicators(PactDslWithProvider builder) {
        var responseForPostCi = newJsonBody(body -> body.stringValue("result", "success")).build();

        return builder.given("mockApiKey is a valid api key")
                .given("mockUserId is the user_id")
                .uponReceiving(
                        "Request for contra-indicators for specific user with existing contra-indicators.")
                .path(POST_CI_ENDPOINT)
                .method("POST")
                .body(String.format("{\"signed_jwt\": \"%s\"}", FAILED_DVLA_VC_WITH_CI_BODY_JWT))
                .headers(
                        X_API_KEY_HEADER,
                        MOCK_API_KEY,
                        IP_ADDRESS_HEADER,
                        MOCK_IP_ADDRESS,
                        GOVUK_SIGNIN_JOURNEY_ID_HEADER,
                        MOCK_GOVUK_SIGNIN_ID,
                        PactDslRequestBase.CONTENT_TYPE,
                        "application/json")
                .willRespondWith()
                .status(200)
                .body(responseForPostCi)
                .toPact();
    }

    @Test
    @PactTestFor(pactMethod = "successfullyPostsContraIndicators")
    void successfullyPostCis_whenCalledWithSignedJwtAgainstCimiApi_returns200(MockServer mockServer)
            throws CiPutException, ParseException, CredentialParseException {
        // Arrange
        when(mockConfigService.getParameter(CIMIT_API_BASE_URL))
                .thenReturn(getMockApiBaseUrl(mockServer));

        var testVc =
                VerifiableCredential.fromValidJwt(
                        MOCK_USER_ID, null, SignedJWT.parse(FAILED_DVLA_VC_WITH_CI_BODY_JWT));

        var underTest = new CiMitService(mockConfigService);

        // Act
        underTest.submitVC(testVc, MOCK_GOVUK_SIGNIN_ID, MOCK_IP_ADDRESS);

        // Assert
    }

    @Pact(provider = "CiMitProvider", consumer = "IpvCoreBack")
    public RequestResponsePact invalidJwtReturns400(PactDslWithProvider builder) {
        var response =
                newJsonBody(
                                body -> {
                                    body.stringValue("result", "fail");
                                    body.stringValue("reason", "BAD_REQUEST");
                                })
                        .build();

        return builder.given("invalid jwt is ")
                .given("mockApiKey is a valid api key")
                .given("mockIpAddress is the ip-address")
                .given("mockGovukSigninJourneyId is the govuk-signin-journey-id")
                .given("mockUserId is the user_id")
                .uponReceiving("Invalid request due to invalid jwt")
                .method("POST")
                .path(POST_CI_ENDPOINT)
                .body(String.format("{\"signed_jwt\": \"%s\"}", INVALID_JWT))
                .headers(
                        X_API_KEY_HEADER,
                        MOCK_API_KEY,
                        IP_ADDRESS_HEADER,
                        MOCK_IP_ADDRESS,
                        GOVUK_SIGNIN_JOURNEY_ID_HEADER,
                        MOCK_GOVUK_SIGNIN_ID,
                        PactDslRequestBase.CONTENT_TYPE,
                        "application/json")
                .willRespondWith()
                .body(response)
                .status(400)
                .toPact();
    }

    @Test
    @PactTestFor(pactMethod = "invalidJwtReturns400")
    void failsToPostCis_whenCalledWithInvalidJwtAgainstCimiApi_returns400(MockServer mockServer)
            throws ParseException, CredentialParseException {
        // Arrange
        when(mockConfigService.getParameter(CIMIT_API_BASE_URL))
                .thenReturn(getMockApiBaseUrl(mockServer));

        // an invalid jwt shouldn't be passed to CiMitService as it would be handled by the
        // VerifiableCredential class
        // but to test CiMit's response to an invalid jwt without errors from VerifiableCredential,
        // we create a test VC
        // from a valid jwt then mock out the call to get the vcString
        var spyTestVc =
                spy(
                        VerifiableCredential.fromValidJwt(
                                MOCK_USER_ID,
                                null,
                                SignedJWT.parse(FAILED_DVLA_VC_WITH_CI_BODY_JWT)));
        when(spyTestVc.getVcString()).thenReturn(INVALID_JWT);

        var underTest = new CiMitService(mockConfigService);

        // Act/Assert
        assertThrows(
                CiPutException.class,
                () -> underTest.submitVC(spyTestVc, MOCK_GOVUK_SIGNIN_ID, MOCK_IP_ADDRESS),
                FAILED_API_REQUEST);
    }

    @Pact(provider = "CiMitProvider", consumer = "IpvCoreBack")
    public RequestResponsePact invalidIssuerReturns400(PactDslWithProvider builder) {
        var response =
                newJsonBody(
                                body -> {
                                    body.stringValue("result", "fail");
                                    body.stringValue("reason", "BAD_VC_ISSUER");
                                })
                        .build();

        return builder.given("invalid jwt is ")
                .given("mockApiKey is a valid api key")
                .given("mockIpAddress is the ip-address")
                .given("mockGovukSigninJourneyId is the govuk-signin-journey-id")
                .given("mockUserId is the user_id")
                .uponReceiving("Invalid request due to invalid issuer")
                .method("POST")
                .path(POST_CI_ENDPOINT)
                .body(String.format("{\"signed_jwt\": \"%s\"}", FAILED_DVLA_VC_WITH_CI_BODY_JWT))
                .headers(
                        X_API_KEY_HEADER,
                        MOCK_API_KEY,
                        IP_ADDRESS_HEADER,
                        MOCK_IP_ADDRESS,
                        GOVUK_SIGNIN_JOURNEY_ID_HEADER,
                        MOCK_GOVUK_SIGNIN_ID,
                        PactDslRequestBase.CONTENT_TYPE,
                        "application/json")
                .willRespondWith()
                .body(response)
                .status(400)
                .toPact();
    }

    @Test
    @PactTestFor(pactMethod = "invalidIssuerReturns400")
    void failsToPostCis_whenCalledWithInvalidIssuerAgainstCimiApi_returns400(MockServer mockServer)
            throws ParseException, CredentialParseException {
        // Arrange
        when(mockConfigService.getParameter(CIMIT_API_BASE_URL))
                .thenReturn(getMockApiBaseUrl(mockServer));

        var testVc =
                spy(
                        VerifiableCredential.fromValidJwt(
                                MOCK_USER_ID,
                                null,
                                SignedJWT.parse(FAILED_DVLA_VC_WITH_CI_BODY_JWT)));

        var underTest = new CiMitService(mockConfigService);

        // Act/Assert
        assertThrows(
                CiPutException.class,
                () -> underTest.submitVC(testVc, MOCK_GOVUK_SIGNIN_ID, MOCK_IP_ADDRESS),
                FAILED_API_REQUEST);
    }

    @Pact(provider = "CiMitProvider", consumer = "IpvCoreBack")
    public RequestResponsePact invalidCiCodeReturns400(PactDslWithProvider builder) {
        var response =
                newJsonBody(
                                body -> {
                                    body.stringValue("result", "fail");
                                    body.stringValue("reason", "BAD_CI_CODE");
                                })
                        .build();

        return builder.given("invalid jwt is ")
                .given("mockApiKey is a valid api key")
                .given("mockIpAddress is the ip-address")
                .given("mockGovukSigninJourneyId is the govuk-signin-journey-id")
                .given("mockUserId is the user_id")
                .uponReceiving("Invalid request due to invalid CI codes")
                .method("POST")
                .path(POST_CI_ENDPOINT)
                .body(
                        String.format(
                                "{\"signed_jwt\": \"%s\"}",
                                DVLA_VC_WITH_CI_AND_INVALID_CI_CODE_JWT))
                .headers(
                        X_API_KEY_HEADER,
                        MOCK_API_KEY,
                        IP_ADDRESS_HEADER,
                        MOCK_IP_ADDRESS,
                        GOVUK_SIGNIN_JOURNEY_ID_HEADER,
                        MOCK_GOVUK_SIGNIN_ID,
                        PactDslRequestBase.CONTENT_TYPE,
                        "application/json")
                .willRespondWith()
                .body(response)
                .status(400)
                .toPact();
    }

    @Test
    @PactTestFor(pactMethod = "invalidCiCodeReturns400")
    void failsToPostCis_whenCalledWithInvalidCiCodesAgainstCimiApi_returns400(MockServer mockServer)
            throws ParseException, CredentialParseException {
        // Arrange
        when(mockConfigService.getParameter(CIMIT_API_BASE_URL))
                .thenReturn(getMockApiBaseUrl(mockServer));

        var testVc =
                spy(
                        VerifiableCredential.fromValidJwt(
                                MOCK_USER_ID,
                                null,
                                SignedJWT.parse(DVLA_VC_WITH_CI_AND_INVALID_CI_CODE_JWT)));

        var underTest = new CiMitService(mockConfigService);

        // Act/Assert
        assertThrows(
                CiPutException.class,
                () -> underTest.submitVC(testVc, MOCK_GOVUK_SIGNIN_ID, MOCK_IP_ADDRESS),
                FAILED_API_REQUEST);
    }

    @Pact(provider = "CiMitProvider", consumer = "IpvCoreBack")
    public RequestResponsePact postCiInternalServerErrorReturns500(PactDslWithProvider builder) {
        var response =
                newJsonBody(
                                body -> {
                                    body.stringValue("result", "fail");
                                    body.stringValue("reason", "INTERNAL_SERVER_ERROR");
                                })
                        .build();

        return builder.given("mockApiKey is a valid api key")
                .given("mockUserId is the user_id")
                .uponReceiving("Request with valid JWT but results in internal server error.")
                .path(POST_CI_ENDPOINT)
                .method("POST")
                .body(String.format("{\"signed_jwt\": \"%s\"}", FAILED_DVLA_VC_WITH_CI_BODY_JWT))
                .headers(
                        X_API_KEY_HEADER,
                        MOCK_API_KEY,
                        IP_ADDRESS_HEADER,
                        MOCK_IP_ADDRESS,
                        GOVUK_SIGNIN_JOURNEY_ID_HEADER,
                        MOCK_GOVUK_SIGNIN_ID,
                        PactDslRequestBase.CONTENT_TYPE,
                        "application/json")
                .willRespondWith()
                .status(500)
                .body(response)
                .toPact();
    }

    @Test
    @PactTestFor(pactMethod = "postCiInternalServerErrorReturns500")
    void failsToPostCis_whenCalledAgainstCimiApi_returns500(MockServer mockServer)
            throws ParseException, CredentialParseException {
        // Arrange
        when(mockConfigService.getParameter(CIMIT_API_BASE_URL))
                .thenReturn(getMockApiBaseUrl(mockServer));

        var testVc =
                spy(
                        VerifiableCredential.fromValidJwt(
                                MOCK_USER_ID,
                                null,
                                SignedJWT.parse(FAILED_DVLA_VC_WITH_CI_BODY_JWT)));

        var underTest = new CiMitService(mockConfigService);

        // Act/Assert
        assertThrows(
                CiPutException.class,
                () -> underTest.submitVC(testVc, MOCK_GOVUK_SIGNIN_ID, MOCK_IP_ADDRESS),
                FAILED_API_REQUEST);
    }

    @Pact(provider = "CiMitProvider", consumer = "IpvCoreBack")
    public RequestResponsePact postMitigationsInvalidJwtReturns400(PactDslWithProvider builder) {
        var response =
                newJsonBody(
                                body -> {
                                    body.stringValue("result", "fail");
                                    body.stringValue("reason", "BAD_REQUEST");
                                })
                        .build();

        return builder.given("mockApiKey is a valid api key")
                .given("mockUserId is the user_id")
                .uponReceiving("Request with valid JWT but results in internal server error.")
                .path(POST_MITIGATIONS_ENDPOINT)
                .method("POST")
                .body(String.format("{\"signed_jwts\": [\"%s\"]}", FAILED_DVLA_VC_WITH_CI_BODY_JWT))
                .headers(
                        X_API_KEY_HEADER,
                        MOCK_API_KEY,
                        IP_ADDRESS_HEADER,
                        MOCK_IP_ADDRESS,
                        GOVUK_SIGNIN_JOURNEY_ID_HEADER,
                        MOCK_GOVUK_SIGNIN_ID,
                        PactDslRequestBase.CONTENT_TYPE,
                        "application/json")
                .willRespondWith()
                .status(400)
                .body(response)
                .toPact();
    }

    @Test
    @PactTestFor(pactMethod = "postMitigationsInvalidJwtReturns400")
    void failsToPostMitigations_whenCalledWithInvalidJwtAgainstCimiApi_returns400(
            MockServer mockServer) throws ParseException, CredentialParseException {
        // Arrange
        when(mockConfigService.getParameter(CIMIT_API_BASE_URL))
                .thenReturn(getMockApiBaseUrl(mockServer));

        var testVc =
                spy(
                        VerifiableCredential.fromValidJwt(
                                MOCK_USER_ID,
                                null,
                                SignedJWT.parse(FAILED_DVLA_VC_WITH_CI_BODY_JWT)));

        var underTest = new CiMitService(mockConfigService);

        // Act/Assert
        assertThrows(
                CiPostMitigationsException.class,
                () ->
                        underTest.submitMitigatingVcList(
                                List.of(testVc), MOCK_GOVUK_SIGNIN_ID, MOCK_IP_ADDRESS),
                FAILED_API_REQUEST);
    }

    @Pact(provider = "CiMitProvider", consumer = "IpvCoreBack")
    public RequestResponsePact postMitigationsInvalidCiCodeReturns400(PactDslWithProvider builder) {
        var response =
                newJsonBody(
                                body -> {
                                    body.stringValue("result", "fail");
                                    body.stringValue("reason", "BAD_CI_CODE");
                                })
                        .build();

        return builder.given("mockApiKey is a valid api key")
                .given("mockUserId is the user_id")
                .uponReceiving("Request with valid JWT but results in internal server error.")
                .path(POST_MITIGATIONS_ENDPOINT)
                .method("POST")
                .body(
                        String.format(
                                "{\"signed_jwts\": [\"%s\"]}",
                                DVLA_VC_WITH_CI_AND_INVALID_CI_CODE_JWT))
                .headers(
                        X_API_KEY_HEADER,
                        MOCK_API_KEY,
                        IP_ADDRESS_HEADER,
                        MOCK_IP_ADDRESS,
                        GOVUK_SIGNIN_JOURNEY_ID_HEADER,
                        MOCK_GOVUK_SIGNIN_ID,
                        PactDslRequestBase.CONTENT_TYPE,
                        "application/json")
                .willRespondWith()
                .status(400)
                .body(response)
                .toPact();
    }

    @Test
    @PactTestFor(pactMethod = "postMitigationsInvalidCiCodeReturns400")
    void failsToPostMitigations_whenCalledAgainstCimiApiResultsInInvalidCiCode_returns400(
            MockServer mockServer) throws ParseException, CredentialParseException {
        // Arrange
        when(mockConfigService.getParameter(CIMIT_API_BASE_URL))
                .thenReturn(getMockApiBaseUrl(mockServer));

        var testVc =
                spy(
                        VerifiableCredential.fromValidJwt(
                                MOCK_USER_ID,
                                null,
                                SignedJWT.parse(DVLA_VC_WITH_CI_AND_INVALID_CI_CODE_JWT)));

        var underTest = new CiMitService(mockConfigService);

        // Act/Assert
        assertThrows(
                CiPostMitigationsException.class,
                () ->
                        underTest.submitMitigatingVcList(
                                List.of(testVc), MOCK_GOVUK_SIGNIN_ID, MOCK_IP_ADDRESS),
                FAILED_API_REQUEST);
    }

    @Pact(provider = "CiMitProvider", consumer = "IpvCoreBack")
    public RequestResponsePact postMitigationsInvalidIssuerReturns400(PactDslWithProvider builder) {
        var response =
                newJsonBody(
                                body -> {
                                    body.stringValue("result", "fail");
                                    body.stringValue("reason", "BAD_VC_ISSUER");
                                })
                        .build();

        return builder.given("mockApiKey is a valid api key")
                .given("mockUserId is the user_id")
                .uponReceiving("Request with valid JWT but results in internal server error.")
                .path(POST_MITIGATIONS_ENDPOINT)
                .method("POST")
                .body(
                        String.format(
                                "{\"signed_jwts\": [\"%s\"]}",
                                DVLA_VC_WITH_CI_AND_INVALID_ISSUER_JWT))
                .headers(
                        X_API_KEY_HEADER,
                        MOCK_API_KEY,
                        IP_ADDRESS_HEADER,
                        MOCK_IP_ADDRESS,
                        GOVUK_SIGNIN_JOURNEY_ID_HEADER,
                        MOCK_GOVUK_SIGNIN_ID,
                        PactDslRequestBase.CONTENT_TYPE,
                        "application/json")
                .willRespondWith()
                .status(400)
                .body(response)
                .toPact();
    }

    @Test
    @PactTestFor(pactMethod = "postMitigationsInvalidIssuerReturns400")
    void failsToPostMitigations_whenCalledWithInvalidIssuerAgainstCimiApi_returns400(
            MockServer mockServer) throws ParseException, CredentialParseException {
        // Arrange
        when(mockConfigService.getParameter(CIMIT_API_BASE_URL))
                .thenReturn(getMockApiBaseUrl(mockServer));

        var testVc =
                spy(
                        VerifiableCredential.fromValidJwt(
                                MOCK_USER_ID,
                                null,
                                SignedJWT.parse(DVLA_VC_WITH_CI_AND_INVALID_ISSUER_JWT)));

        var underTest = new CiMitService(mockConfigService);

        // Act/Assert
        assertThrows(
                CiPostMitigationsException.class,
                () ->
                        underTest.submitMitigatingVcList(
                                List.of(testVc), MOCK_GOVUK_SIGNIN_ID, MOCK_IP_ADDRESS),
                FAILED_API_REQUEST);
    }

    @Pact(provider = "CiMitProvider", consumer = "IpvCoreBack")
    public RequestResponsePact postMitigationsInternalServerErrorReturns500(
            PactDslWithProvider builder) {
        var response =
                newJsonBody(
                                body -> {
                                    body.stringValue("result", "fail");
                                    body.stringValue("reason", "INTERNAL_SERVER_ERROR");
                                })
                        .build();

        return builder.given("mockApiKey is a valid api key")
                .given("mockUserId is the user_id")
                .uponReceiving("Request with valid JWTs but results in internal server error.")
                .path(POST_MITIGATIONS_ENDPOINT)
                .method("POST")
                .body(String.format("{\"signed_jwts\": [\"%s\"]}", FAILED_DVLA_VC_WITH_CI_BODY_JWT))
                .headers(
                        X_API_KEY_HEADER,
                        MOCK_API_KEY,
                        IP_ADDRESS_HEADER,
                        MOCK_IP_ADDRESS,
                        GOVUK_SIGNIN_JOURNEY_ID_HEADER,
                        MOCK_GOVUK_SIGNIN_ID,
                        PactDslRequestBase.CONTENT_TYPE,
                        "application/json")
                .willRespondWith()
                .status(500)
                .body(response)
                .toPact();
    }

    @Test
    @PactTestFor(pactMethod = "postMitigationsInternalServerErrorReturns500")
    void failsToPostMitigations_whenCalledAgainstCimiApi_returns500(MockServer mockServer)
            throws ParseException, CredentialParseException {
        // Arrange
        when(mockConfigService.getParameter(CIMIT_API_BASE_URL))
                .thenReturn(getMockApiBaseUrl(mockServer));

        var testVc =
                spy(
                        VerifiableCredential.fromValidJwt(
                                MOCK_USER_ID,
                                null,
                                SignedJWT.parse(FAILED_DVLA_VC_WITH_CI_BODY_JWT)));

        var underTest = new CiMitService(mockConfigService);

        // Act/Assert
        assertThrows(
                CiPostMitigationsException.class,
                () ->
                        underTest.submitMitigatingVcList(
                                List.of(testVc), MOCK_GOVUK_SIGNIN_ID, MOCK_IP_ADDRESS),
                FAILED_API_REQUEST);
    }

    //    @Pact(provider = "CiMitProvider", consumer = "IpvCoreBack")
    //    public RequestResponsePact successfullyReceivesMitigations(PactDslWithProvider builder) {
    //        var responseForPostMi =
    //                newJsonBody(
    //                        body -> {
    //                            body.stringValue("result", "success");
    //                        })
    //                        .build();
    //
    //        return builder.given("mockApiKey is a valid api key")
    //                .given("mockUserId is a valid user_id")
    //                .uponReceiving(
    //                        "Request for contra-indicators for specific user with existing
    // contra-indicators.")
    //                .path(POST_MITIGATIONS_ENDPOINT)
    //                .headers(
    //                        X_API_KEY_HEADER,
    //                        MOCK_API_KEY,
    //                        IP_ADDRESS_HEADER,
    //                        MOCK_IP_ADDRESS,
    //                        GOVUK_SIGNIN_JOURNEY_ID_HEADER,
    //                        MOCK_GOVUK_SIGNIN_ID,
    //                        PactDslRequestBase.CONTENT_TYPE,
    //                        "application/json")
    //                .willRespondWith()
    //                .status(200)
    //                .body(responseForPostMi)
    //                .toPact();
    //    }

    private String getMockApiBaseUrl(MockServer mockServer) {
        return MOCK_SERVER_BASE_URL + mockServer.getPort();
    }

    private static final String MOCK_IP_ADDRESS = "mockIpAddress";
    private static final String MOCK_USER_ID = "mockUserId";
    private static final String MOCK_GOVUK_SIGNIN_ID = "mockGovukSigninJourneyId";
    private static final String MOCK_API_KEY = "mockApiKey"; // pragma: allowlist secret
    private static final String MOCK_SERVER_BASE_URL = "http://localhost:";
    private static final String TEST_ISSUER = "mockCimitComponentId";
    private static final String INVALID_JWT = "invalidJwt";

    private static final String VALID_VC_HEADER =
            """
            {
              "alg": "ES256",
              "typ": "JWT"
            }
            """;

    // TODO: confirm with ticf team if this is the shape of the data they expect
    // 2010-01-01 00:00:00 is 1262304000 in epoch seconds
    private static final String VALID_CI_VC_BODY =
            """
            {
              "sub": "mockUserId",
              "nbf": 1262304000,
              "iss": "mockCimitComponentId",
              "exp": 2005303168,
              "iat": 1262304000,
              "vc": {
                "evidence": [
                  {
                    "contraIndicator": [
                      {
                        "mitigation": [
                          {
                            "mitigatingCredential": [
                              {
                                "validFrom": "2010-01-01T00:00:00.000Z",
                                "txn": "ghij",
                                "id": "urn:uuid:f81d4fae-7dec-11d0-a765-00a0c91e6bf6",
                                "issuer": "https://credential-issuer.example/"
                              }
                            ],
                            "code": "some-code"
                          }
                        ],
                        "code": "some-code",
                        "issuers": [
                          "https://issuing-cri.example"
                        ],
                        "incompleteMitigation": [
                          {
                            "mitigatingCredential": [
                              {
                                "validFrom": "2010-01-01T00:00:00.000Z",
                                "txn": "cdeef",
                                "id": "urn:uuid:f5c9ff40-1dcd-4a8b-bf92-9456047c132f",
                                "issuer": "https://another-credential-issuer.example/"
                              }
                            ],
                            "code": "some-code"
                          }
                        ],
                        "issuanceDate": "2010-01-01T00:00:00.000Z",
                        "document": "passport/GBR/824159121",
                        "txn": [
                          "abcdef"
                        ]
                      }
                    ],
                    "txn": [
                      "fkfkd"
                    ],
                    "type": "SecurityCheck"
                  }
                ],
                "type": [
                  "VerifiableCredential",
                  "SecurityCheckCredential"
                ]
              }
            }
            """;

    // If we generate the signature in code it will be different each time, so we need to generate a
    // valid signature (using https://jwt.io works well) and record it here so the PACT file doesn't
    // change each time we run the tests.
    private static final String VALID_CI_VC_SIGNATURE =
            "sQxm1obDLvcytC1SxyZZABYLpPvWG15tYmAGYTv8KrPhfB7oAut04AH1TumrTmjuQmkzgyEVgYms9YtH-f6Fkg"; // pragma: allowlist secret

    // 2099-01-01 00:00:00 is 4070908800 in epoch seconds
    // From DCMAW-5477-AC1
    private static final String FAILED_DVLA_VC_WITH_CI_BODY =
            """
            {
              "iat": 1712228728,
              "iss": "mockCimitComponentId",
              "aud": "issuer",
              "sub": "test-subject",
              "nbf": 4070908800,
              "jti": "urn:uuid:c5b7c1b0-8262-4d57-b168-9bc94568af17",
              "vc": {
                "type": [
                  "VerifiableCredential",
                  "IdentityCheckCredential"
                ],
                "credentialSubject": {
                  "name": [
                    {
                      "nameParts": [
                        {
                          "value": "Jane",
                          "type": "GivenName"
                        },
                        {
                          "value": "Doe",
                          "type": "FamilyName"
                        }
                      ]
                    }
                  ],
                  "birthDate": [
                    {
                      "value": "1981-11-28"
                    }
                  ],
                  "deviceId": [
                    {
                      "value": "fb03ce33-6cb4-4b27-b428-f614eba26dd0"
                    }
                  ],
                  "address": [
                    {
                      "uprn": null,
                      "organisationName": null,
                      "subBuildingName": null,
                      "buildingNumber": null,
                      "buildingName": null,
                      "dependentStreetName": null,
                      "streetName": null,
                      "doubleDependentAddressLocality": null,
                      "dependentAddressLocality": null,
                      "addressLocality": null,
                      "postalCode": "CH62 6AQ",
                      "addressCountry": null
                    }
                  ],
                  "drivingPermit": [
                    {
                      "personalNumber": "DOEDO861281JF9DH",
                      "issueNumber": null,
                      "issuedBy": "DVLA",
                      "issueDate": null,
                      "expiryDate": "2028-08-07",
                      "fullAddress": "102 TEST ROAD,WIRRAL,CH62 6AQ"
                    }
                  ]
                },
                "evidence": [
                  {
                    "type": "IdentityCheck",
                    "txn": "bcd2346",
                    "strengthScore": 3,
                    "validityScore": 0,
                    "ci": [
                      "TEST-CI-CODE"
                    ],
                    "activityHistoryScore": 0,
                    "failedCheckDetails": [
                      {
                        "checkMethod": "vri",
                        "identityCheckPolicy": "published",
                        "activityFrom": null
                      },
                      {
                        "checkMethod": "bvr",
                        "biometricVerificationProcessLevel": 3
                      }
                    ]
                  }
                ]
              },
              "exp": 4070909400
            }
            """;

    private static final String FAILED_DVLA_VC_WITH_CI_BODY_SIGNATURE =
            "PR1jYFN4AfDlkXBQQgnOqMDtTtS7QH_-xGn15lGXy1Nz8gdrhs0wEyIHf7xIPUA-j1ZqRiJF9kudmHfRwXOyqg"; // pragma: allowlist secret
    private static final String FAILED_DVLA_VC_WITH_CI_BODY_JWT =
            new PactJwtBuilder(
                            VALID_VC_HEADER,
                            FAILED_DVLA_VC_WITH_CI_BODY,
                            FAILED_DVLA_VC_WITH_CI_BODY_SIGNATURE)
                    .buildJwt();

    // 2099-01-01 00:00:00 is 4070908800 in epoch seconds
    // From DCMAW-5477-AC1
    private static final String DVLA_VC_WITH_CI_AND_INVALID_ISSUER =
            """
            {
              "iat": 1712228728,
              "iss": "invalidIssuer",
              "aud": "issuer",
              "sub": "test-subject",
              "nbf": 4070908800,
              "jti": "urn:uuid:c5b7c1b0-8262-4d57-b168-9bc94568af17",
              "vc": {
                "type": [
                  "VerifiableCredential",
                  "IdentityCheckCredential"
                ],
                "credentialSubject": {
                  "name": [
                    {
                      "nameParts": [
                        {
                          "value": "Jane",
                          "type": "GivenName"
                        },
                        {
                          "value": "Doe",
                          "type": "FamilyName"
                        }
                      ]
                    }
                  ],
                  "birthDate": [
                    {
                      "value": "1981-11-28"
                    }
                  ],
                  "deviceId": [
                    {
                      "value": "fb03ce33-6cb4-4b27-b428-f614eba26dd0"
                    }
                  ],
                  "address": [
                    {
                      "uprn": null,
                      "organisationName": null,
                      "subBuildingName": null,
                      "buildingNumber": null,
                      "buildingName": null,
                      "dependentStreetName": null,
                      "streetName": null,
                      "doubleDependentAddressLocality": null,
                      "dependentAddressLocality": null,
                      "addressLocality": null,
                      "postalCode": "CH62 6AQ",
                      "addressCountry": null
                    }
                  ],
                  "drivingPermit": [
                    {
                      "personalNumber": "DOEDO861281JF9DH",
                      "issueNumber": null,
                      "issuedBy": "DVLA",
                      "issueDate": null,
                      "expiryDate": "2028-08-07",
                      "fullAddress": "102 TEST ROAD,WIRRAL,CH62 6AQ"
                    }
                  ]
                },
                "evidence": [
                  {
                    "type": "IdentityCheck",
                    "txn": "bcd2346",
                    "strengthScore": 3,
                    "validityScore": 0,
                    "ci": [
                      "TEST-CI-CODE"
                    ],
                    "activityHistoryScore": 0,
                    "failedCheckDetails": [
                      {
                        "checkMethod": "vri",
                        "identityCheckPolicy": "published",
                        "activityFrom": null
                      },
                      {
                        "checkMethod": "bvr",
                        "biometricVerificationProcessLevel": 3
                      }
                    ]
                  }
                ]
              },
              "exp": 4070909400
            }
            """;

    private static final String DVLA_VC_WITH_CI_AND_INVALID_ISSUER_SIGNATURE =
            "w0P6_uhj1wOo5EFSi5_I1bLAe0zwpIvw_w8mSdV9DhXKdcHcRWGI6sd4TlvmekI88hJgIhyGs08OECTgPCtOmw"; // pragma: allowlist secret
    private static final String DVLA_VC_WITH_CI_AND_INVALID_ISSUER_JWT =
            new PactJwtBuilder(
                            VALID_VC_HEADER,
                            DVLA_VC_WITH_CI_AND_INVALID_ISSUER,
                            DVLA_VC_WITH_CI_AND_INVALID_ISSUER_SIGNATURE)
                    .buildJwt();

    // 2099-01-01 00:00:00 is 4070908800 in epoch seconds
    // From DCMAW-5477-AC1
    private static final String DVLA_VC_WITH_CI_AND_INVALID_CI_CODE =
            """
            {
              "iat": 1712228728,
              "iss": "invalidIssuer",
              "aud": "issuer",
              "sub": "test-subject",
              "nbf": 4070908800,
              "jti": "urn:uuid:c5b7c1b0-8262-4d57-b168-9bc94568af17",
              "vc": {
                "type": [
                  "VerifiableCredential",
                  "IdentityCheckCredential"
                ],
                "credentialSubject": {
                  "name": [
                    {
                      "nameParts": [
                        {
                          "value": "Jane",
                          "type": "GivenName"
                        },
                        {
                          "value": "Doe",
                          "type": "FamilyName"
                        }
                      ]
                    }
                  ],
                  "birthDate": [
                    {
                      "value": "1981-11-28"
                    }
                  ],
                  "deviceId": [
                    {
                      "value": "fb03ce33-6cb4-4b27-b428-f614eba26dd0"
                    }
                  ],
                  "address": [
                    {
                      "uprn": null,
                      "organisationName": null,
                      "subBuildingName": null,
                      "buildingNumber": null,
                      "buildingName": null,
                      "dependentStreetName": null,
                      "streetName": null,
                      "doubleDependentAddressLocality": null,
                      "dependentAddressLocality": null,
                      "addressLocality": null,
                      "postalCode": "CH62 6AQ",
                      "addressCountry": null
                    }
                  ],
                  "drivingPermit": [
                    {
                      "personalNumber": "DOEDO861281JF9DH",
                      "issueNumber": null,
                      "issuedBy": "DVLA",
                      "issueDate": null,
                      "expiryDate": "2028-08-07",
                      "fullAddress": "102 TEST ROAD,WIRRAL,CH62 6AQ"
                    }
                  ]
                },
                "evidence": [
                  {
                    "type": "IdentityCheck",
                    "txn": "bcd2346",
                    "strengthScore": 3,
                    "validityScore": 0,
                    "ci": [
                      "INVALID-CI-CODE"
                    ],
                    "activityHistoryScore": 0,
                    "failedCheckDetails": [
                      {
                        "checkMethod": "vri",
                        "identityCheckPolicy": "published",
                        "activityFrom": null
                      },
                      {
                        "checkMethod": "bvr",
                        "biometricVerificationProcessLevel": 3
                      }
                    ]
                  }
                ]
              },
              "exp": 4070909400
            }
            """;

    private static final String DVLA_VC_WITH_CI_AND_INVALID_CI_CODE_SIGNATURE =
            "35BYZ0S4B4up9NebIyeC4Tz09Xd-A1IuGDCjyhEDeesALdc1MO3tkrR_McXo8gn9xnJxWB4s_E1NUW8I7altUQ"; // pragma: allowlist secret
    private static final String DVLA_VC_WITH_CI_AND_INVALID_CI_CODE_JWT =
            new PactJwtBuilder(
                            VALID_VC_HEADER,
                            DVLA_VC_WITH_CI_AND_INVALID_CI_CODE,
                            DVLA_VC_WITH_CI_AND_INVALID_CI_CODE_SIGNATURE)
                    .buildJwt();
}
