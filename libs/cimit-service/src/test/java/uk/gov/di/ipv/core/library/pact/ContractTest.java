package uk.gov.di.ipv.core.library.pact;

import au.com.dius.pact.consumer.MockServer;
import au.com.dius.pact.consumer.dsl.DslPart;
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
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.CIMIT_API_BASE_URL;
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
    }

    @Pact(provider = "CiMitProvider", consumer = "IpvCoreBack")
    public RequestResponsePact getCisUserIdReturnsContraIndicators(PactDslWithProvider builder) {
        var responseForGetCi = newJsonBody(body -> body.stringValue("vc", VALID_CI_VC_JWT)).build();

        return builder.given("mockUserId is the user_id")
                .given("the current time is 2024-01-01 00:00:00")
                .given("mockCimitComponentId is the issuer")
                .given("a contra-indicator is returned with code TEST-CI-CODE-2 for a passport")
                .given("the passport has issue date 2024-08-05T14:59:03.000Z")
                .given("the passport has document number 12345678")
                .given("the mitigation has code TEST02")
                .given("the mitigation is valid from 2024-08-05T14:59:05.000Z")
                .given("the mitigation has no incomplete mitigations")
                .given("a contra-indicator is returned with code TEST-CI-CODE-1 for an id card")
                .given("the id card has issue date 2024-08-05T14:59:04.000Z")
                .given("the id card has document number 852654")
                .given("the mitigation has code TEST01")
                .given("the mitigation is valid from 2024-08-05T14:59:05.000Z")
                .given("the mitigation has no incomplete mitigations")
                .uponReceiving(
                        "Request for contra-indicators for specific user with existing contra-indicators.")
                .path(GET_VCS_ENDPOINT)
                .query("user_id=" + MOCK_USER_ID)
                .method("GET")
                .headers(
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
    @PactTestFor(pactMethod = "getCisUserIdReturnsContraIndicators")
    void fetchContraIndicators_whenCalledWithUserIdAgainstCimiApi_receivesContraIndicators(
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

        assertEquals(evidence.getContraIndicator().size(), 2);
        assertEquals(evidence.getContraIndicator().get(0).getDocument(), "idCard/FRE/852654");
        assertEquals(evidence.getContraIndicator().get(0).getCode(), "TEST-CI-CODE-1");
        assertEquals(evidence.getContraIndicator().get(0).getMitigation().size(), 1);
        assertEquals(
                evidence.getContraIndicator().get(0).getMitigation().get(0).getCode(), "TEST01");

        assertEquals(evidence.getContraIndicator().get(1).getDocument(), "passport/GBR/12345678");
        assertEquals(evidence.getContraIndicator().get(1).getCode(), "TEST-CI-CODE-2");
        assertEquals(evidence.getContraIndicator().get(1).getMitigation().size(), 1);
        assertEquals(
                evidence.getContraIndicator().get(1).getMitigation().get(0).getCode(), "TEST02");
    }

    @Pact(provider = "CiMitProvider", consumer = "IpvCoreBack")
    public RequestResponsePact getCisUserIdReturnsNoCisVc(PactDslWithProvider builder) {
        var responseForGetCi =
                newJsonBody(body -> body.stringValue("vc", VALID_NO_CI_VC_JWT)).build();

        return builder.given("mockUserId is the user_id")
                .given("the current time is 2024-01-01 00:00:00")
                .given("mockCimitComponentId is the issuer")
                .given("there are no contra-indicators")
                .given("expiry is 2099-01-01 00:00:00")
                .given("a contra-indicator is returned with code TEST-CI-CODE-2 for a passport")
                .uponReceiving("Request for contra-indicators for user with no contra-indicators.")
                .path(GET_VCS_ENDPOINT)
                .query("user_id=" + MOCK_USER_ID)
                .method("GET")
                .headers(
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
    @PactTestFor(pactMethod = "getCisUserIdReturnsNoCisVc")
    void fetchContraIndicators_whenCalledWithUserIdAgainstCimiApi_receivesEmptyContraIndicators(
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

        assertEquals(evidence.getContraIndicator().size(), 0);
    }

    @Pact(provider = "CiMitProvider", consumer = "IpvCoreBack")
    public RequestResponsePact getCisInternalServerErrorReturns500(PactDslWithProvider builder) {
        var responseForGetCi = getFailedApiResponse("INTERNAL_ERROR");

        return builder.given("mockUserId is the user_id")
                .given("the current time is 2024-01-01 00:00:00")
                .given("mockCimitComponentId is the issuer")
                .given("a contra-indicator is returned with code TEST-CI-CODE-2 for a passport")
                .given("the passport has issue date 2024-08-05T14:59:03.000Z")
                .given("the passport has document number 12345678")
                .given("the mitigation with code TEST02")
                .given("the mitigation is valid from 2024-08-05T14:59:05.000Z")
                .given("the mitigation has no incomplete mitigations")
                .given("a contra-indicator is returned with code TEST-CI-CODE-1 for an id card")
                .given("the id card has issue date 2024-08-05T14:59:04.000Z")
                .given("the id card has document number 852654")
                .given("the mitigation with code TEST01")
                .given("the mitigation is valid from 2024-08-05T14:59:05.000Z")
                .given("the mitigation has no incomplete mitigations")
                .uponReceiving(
                        "Request for contra-indicators for specific user with existing contra-indicators.")
                .path(GET_VCS_ENDPOINT)
                .query("user_id=" + MOCK_USER_ID)
                .method("GET")
                .headers(
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
    @PactTestFor(pactMethod = "getCisInternalServerErrorReturns500")
    void
            fetchContraIndicatorsFails_whenCalledWithValidUserIdAgainstCimiApiResultsInInternalServerError_returns500(
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
    public RequestResponsePact postCiSuccessfullyPostsContraIndicator(PactDslWithProvider builder) {
        var responseForPostCi = newJsonBody(body -> body.stringValue("result", "success")).build();

        return builder.given("mockUserId is the user")
                .given("mockCimitComponentId is the issuer")
                .given("the current time is 2024-01-01 00:00:00")
                .given("the VC is from DCMAW-5477-AC1")
                .given("the VC has CI code TEST-CI-CODE")
                .uponReceiving(
                        "Request for contra-indicators for specific user with existing contra-indicators.")
                .path(POST_CI_ENDPOINT)
                .method("POST")
                .body(String.format("{\"signed_jwt\": \"%s\"}", FAILED_DVLA_VC_WITH_CI_JWT))
                .headers(
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
    @PactTestFor(pactMethod = "postCiSuccessfullyPostsContraIndicator")
    void successfullyPostCis_whenCalledWithSignedJwtAgainstCimiApi_returns200(MockServer mockServer)
            throws ParseException, CredentialParseException {
        // Arrange
        when(mockConfigService.getParameter(CIMIT_API_BASE_URL))
                .thenReturn(getMockApiBaseUrl(mockServer));

        var testVc =
                VerifiableCredential.fromValidJwt(
                        MOCK_USER_ID, null, SignedJWT.parse(FAILED_DVLA_VC_WITH_CI_JWT));

        var underTest = new CiMitService(mockConfigService);

        // Act
        assertDoesNotThrow(() -> underTest.submitVC(testVc, MOCK_GOVUK_SIGNIN_ID, MOCK_IP_ADDRESS));
    }

    @Pact(provider = "CiMitProvider", consumer = "IpvCoreBack")
    public RequestResponsePact postCiInvalidJwtReturns400(PactDslWithProvider builder) {
        var response = getFailedApiResponse("BAD_REQUEST");

        return builder.given("invalidJwt is the signed_jwt")
                .given("mockIpAddress is the ip-address")
                .given("mockGovukSigninJourneyId is the govuk-signin-journey-id")
                .given("mockUserId is the user_id")
                .uponReceiving("Request with invalid jwt")
                .method("POST")
                .path(POST_CI_ENDPOINT)
                .body(String.format("{\"signed_jwt\": \"%s\"}", INVALID_JWT))
                .headers(
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
    @PactTestFor(pactMethod = "postCiInvalidJwtReturns400")
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
                                MOCK_USER_ID, null, SignedJWT.parse(FAILED_DVLA_VC_WITH_CI_JWT)));
        when(spyTestVc.getVcString()).thenReturn(INVALID_JWT);

        var underTest = new CiMitService(mockConfigService);

        // Act/Assert
        assertThrows(
                CiPutException.class,
                () -> underTest.submitVC(spyTestVc, MOCK_GOVUK_SIGNIN_ID, MOCK_IP_ADDRESS),
                FAILED_API_REQUEST);
    }

    @Pact(provider = "CiMitProvider", consumer = "IpvCoreBack")
    public RequestResponsePact postCiInvalidSignatureReturns400(PactDslWithProvider builder) {
        var response = getFailedApiResponse("BAD_VC_SIGNATURE");

        return builder.given("signed_jwt has invalid signature invalidSignature")
                .given("mockIpAddress is the ip-address")
                .given("mockCimitComponentId is the issuer")
                .given("mockGovukSigninJourneyId is the govuk-signin-journey-id")
                .given("mockUserId is the user_id")
                .uponReceiving("Request with invalid signature")
                .method("POST")
                .path(POST_CI_ENDPOINT)
                .body(
                        String.format(
                                "{\"signed_jwt\": \"%s\"}",
                                FAILED_DVLA_VC_WITH_CI_JWT_WITH_INVALID_SIGNATURE))
                .headers(
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
    @PactTestFor(pactMethod = "postCiInvalidSignatureReturns400")
    void failsToPostCis_whenCalledWithInvalidSignatureAgainstCimiApi_returns400(
            MockServer mockServer) throws ParseException, CredentialParseException {
        // Arrange
        when(mockConfigService.getParameter(CIMIT_API_BASE_URL))
                .thenReturn(getMockApiBaseUrl(mockServer));

        // an invalid signature shouldn't be passed to CiMitService as it would be handled by the
        // VerifiableCredential class
        // but to test CiMit's response to an invalid signature without errors from
        // VerifiableCredential,
        // we create a test VC
        // from a valid jwt then mock out the call to get the vcString, replacing with a jwt with
        // invalid signature
        var spyTestVc =
                spy(
                        VerifiableCredential.fromValidJwt(
                                MOCK_USER_ID, null, SignedJWT.parse(FAILED_DVLA_VC_WITH_CI_JWT)));
        when(spyTestVc.getVcString()).thenReturn(FAILED_DVLA_VC_WITH_CI_JWT_WITH_INVALID_SIGNATURE);

        var underTest = new CiMitService(mockConfigService);

        // Act/Assert
        assertThrows(
                CiPutException.class,
                () -> underTest.submitVC(spyTestVc, MOCK_GOVUK_SIGNIN_ID, MOCK_IP_ADDRESS),
                FAILED_API_REQUEST);
    }

    @Pact(provider = "CiMitProvider", consumer = "IpvCoreBack")
    public RequestResponsePact postCiInvalidIssuerReturns400(PactDslWithProvider builder) {
        var response = getFailedApiResponse("BAD_VC_ISSUER");

        return builder.given("mockIpAddress is the ip-address")
                .given("mockGovukSigninJourneyId is the govuk-signin-journey-id")
                .given("mockUserId is the user_id")
                .given("invalidIssuer is the issuer")
                .given("the VC is from DCMAW-5477-AC1")
                .given("the VC has CI code TEST-CI-CODE")
                .uponReceiving("Request with invalid issuer")
                .method("POST")
                .path(POST_CI_ENDPOINT)
                .body(String.format("{\"signed_jwt\": \"%s\"}", FAILED_DVLA_VC_WITH_CI_JWT))
                .headers(
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
    @PactTestFor(pactMethod = "postCiInvalidIssuerReturns400")
    void failsToPostCis_whenCalledWithInvalidIssuerAgainstCimiApi_returns400(MockServer mockServer)
            throws ParseException, CredentialParseException {
        // Arrange
        when(mockConfigService.getParameter(CIMIT_API_BASE_URL))
                .thenReturn(getMockApiBaseUrl(mockServer));

        var testVc =
                spy(
                        VerifiableCredential.fromValidJwt(
                                MOCK_USER_ID, null, SignedJWT.parse(FAILED_DVLA_VC_WITH_CI_JWT)));

        var underTest = new CiMitService(mockConfigService);

        // Act/Assert
        assertThrows(
                CiPutException.class,
                () -> underTest.submitVC(testVc, MOCK_GOVUK_SIGNIN_ID, MOCK_IP_ADDRESS),
                FAILED_API_REQUEST);
    }

    @Pact(provider = "CiMitProvider", consumer = "IpvCoreBack")
    public RequestResponsePact postCiInvalidCiCodeReturns400(PactDslWithProvider builder) {
        var response = getFailedApiResponse("BAD_CI_CODE");

        return builder.given("mockIpAddress is the ip-address")
                .given("mockGovukSigninJourneyId is the govuk-signin-journey-id")
                .given("mockUserId is the user_id")
                .given("mockCimitComponentId is the issuer")
                .given("the VC is from DCMAW-5477-AC1")
                .given("the VC has CI code INVALID-CI-CODE")
                .uponReceiving("Request with invalid CI code")
                .method("POST")
                .path(POST_CI_ENDPOINT)
                .body(
                        String.format(
                                "{\"signed_jwt\": \"%s\"}",
                                DVLA_VC_WITH_CI_AND_INVALID_CI_CODE_JWT))
                .headers(
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
    @PactTestFor(pactMethod = "postCiInvalidCiCodeReturns400")
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
        var response = getFailedApiResponse("INTERNAL_SERVER_ERROR");

        return builder.given("mockIpAddress is the ip-address")
                .given("mockGovukSigninJourneyId is the govuk-signin-journey-id")
                .given("mockUserId is the user_id")
                .given("mockCimitComponentId is the issuer")
                .given("the VC is from DCMAW-5477-AC1")
                .given("the VC has CI code TEST-CI-CODE")
                .uponReceiving("Request with valid JWT but results in internal server error.")
                .path(POST_CI_ENDPOINT)
                .method("POST")
                .body(String.format("{\"signed_jwt\": \"%s\"}", FAILED_DVLA_VC_WITH_CI_JWT))
                .headers(
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
                                MOCK_USER_ID, null, SignedJWT.parse(FAILED_DVLA_VC_WITH_CI_JWT)));

        var underTest = new CiMitService(mockConfigService);

        // Act/Assert
        assertThrows(
                CiPutException.class,
                () -> underTest.submitVC(testVc, MOCK_GOVUK_SIGNIN_ID, MOCK_IP_ADDRESS),
                FAILED_API_REQUEST);
    }

    @Pact(provider = "CiMitProvider", consumer = "IpvCoreBack")
    public RequestResponsePact successfullyReceivesMitigations(PactDslWithProvider builder) {
        var response =
                newJsonBody(
                                body -> {
                                    body.stringValue("result", "success");
                                })
                        .build();

        return builder.given("mockIpAddress is the ip-address")
                .given("mockGovukSigninJourneyId is the govuk-signin-journey-id")
                .given("mockUserId is the user_id")
                .given("mockCimitComponentId is the issuer")
                .given("signed_jwts has only one encoded VC")
                .given("the encoded VC is from DCMAW-5477-AC1")
                .given("the VC has CI code TEST-CI-CODE")
                .uponReceiving("Valid request to post signed_jwts.")
                .path(POST_MITIGATIONS_ENDPOINT)
                .method("POST")
                .body(String.format("{\"signed_jwts\": [\"%s\"]}", FAILED_DVLA_VC_WITH_CI_JWT))
                .headers(
                        IP_ADDRESS_HEADER,
                        MOCK_IP_ADDRESS,
                        GOVUK_SIGNIN_JOURNEY_ID_HEADER,
                        MOCK_GOVUK_SIGNIN_ID,
                        PactDslRequestBase.CONTENT_TYPE,
                        "application/json")
                .willRespondWith()
                .status(200)
                .body(response)
                .toPact();
    }

    @Test
    @PactTestFor(pactMethod = "successfullyReceivesMitigations")
    void successfullyPostsMitigations_whenCalledWithSignedJwtAgainstCimiApi_returns200(
            MockServer mockServer) throws ParseException, CredentialParseException {
        // Arrange
        when(mockConfigService.getParameter(CIMIT_API_BASE_URL))
                .thenReturn(getMockApiBaseUrl(mockServer));

        var testVc =
                VerifiableCredential.fromValidJwt(
                        MOCK_USER_ID, null, SignedJWT.parse(FAILED_DVLA_VC_WITH_CI_JWT));

        var underTest = new CiMitService(mockConfigService);

        // Act
        assertDoesNotThrow(
                () ->
                        underTest.submitMitigatingVcList(
                                List.of(testVc), MOCK_GOVUK_SIGNIN_ID, MOCK_IP_ADDRESS));
    }

    @Pact(provider = "CiMitProvider", consumer = "IpvCoreBack")
    public RequestResponsePact postMitigationsInvalidJwtReturns400(PactDslWithProvider builder) {
        var response = getFailedApiResponse("BAD_REQUEST");

        return builder.given("mockIpAddress is the ip-address")
                .given("mockGovukSigninJourneyId is the govuk-signin-journey-id")
                .given("mockUserId is the user_id")
                .given("mockCimitComponentId is the issuer")
                .given("signed_jwts has only one encoded VC")
                .given("invalidJwt is the encoded VC")
                .uponReceiving("Request with invalid jwt")
                .path(POST_MITIGATIONS_ENDPOINT)
                .method("POST")
                .body(String.format("{\"signed_jwts\": [\"%s\"]}", FAILED_DVLA_VC_WITH_CI_JWT))
                .headers(
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
                                MOCK_USER_ID, null, SignedJWT.parse(FAILED_DVLA_VC_WITH_CI_JWT)));

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
        var response = getFailedApiResponse("BAD_CI_CODE");

        return builder.given("mockIpAddress is the ip-address")
                .given("mockGovukSigninJourneyId is the govuk-signin-journey-id")
                .given("mockUserId is the user_id")
                .given("mockCimitComponentId is the issuer")
                .given("signed_jwts has only one encoded VC")
                .given("the encoded VC is from DCMAW-5477-AC1")
                .given("the VC has CI code INVALID-CI-CODE")
                .uponReceiving("Request with invalid CI code.")
                .path(POST_MITIGATIONS_ENDPOINT)
                .method("POST")
                .body(
                        String.format(
                                "{\"signed_jwts\": [\"%s\"]}",
                                DVLA_VC_WITH_CI_AND_INVALID_CI_CODE_JWT))
                .headers(
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
    void failsToPostMitigations_whenCalledWithInvalidCiCodesAgainstCimiApi_returns400(
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
        var response = getFailedApiResponse("BAD_VC_ISSUER");

        return builder.given("mockIpAddress is the ip-address")
                .given("mockGovukSigninJourneyId is the govuk-signin-journey-id")
                .given("mockUserId is the user_id")
                .given("invalidIssuer is the issuer")
                .given("signed_jwts has only one encoded VC")
                .given("the encoded VC is from DCMAW-5477-AC1")
                .given("the VC has CI code TEST-CI-CODE")
                .uponReceiving("Request with invalid issuer.")
                .path(POST_MITIGATIONS_ENDPOINT)
                .method("POST")
                .body(
                        String.format(
                                "{\"signed_jwts\": [\"%s\"]}",
                                DVLA_VC_WITH_CI_AND_INVALID_ISSUER_JWT))
                .headers(
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
    public RequestResponsePact postMitigationsInvalidSignatureReturns400(
            PactDslWithProvider builder) {
        var response = getFailedApiResponse("BAD_VC_SIGNATURE");

        return builder.given("mockIpAddress is the ip-address")
                .given("mockGovukSigninJourneyId is the govuk-signin-journey-id")
                .given("mockUserId is the user_id")
                .given("mockCimitComponentId is the issuer")
                .given("signed_jwts has only one encoded VC")
                .given("the encoded VC has signature invalidSignature")
                .uponReceiving("Request contains jwt with invalid signature.")
                .method("POST")
                .path(POST_MITIGATIONS_ENDPOINT)
                .body(
                        String.format(
                                "{\"signed_jwts\": [\"%s\"]}",
                                FAILED_DVLA_VC_WITH_CI_JWT_WITH_INVALID_SIGNATURE))
                .headers(
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
    @PactTestFor(pactMethod = "postMitigationsInvalidSignatureReturns400")
    void failsToPostMitigations_whenCalledWithInvalidSignatureAgainstCimiApi_returns400(
            MockServer mockServer) throws ParseException, CredentialParseException {
        // Arrange
        when(mockConfigService.getParameter(CIMIT_API_BASE_URL))
                .thenReturn(getMockApiBaseUrl(mockServer));

        // an invalid signature shouldn't be passed to CiMitService as it would be handled by the
        // VerifiableCredential class
        // but to test CiMit's response to an invalid signature without errors from
        // VerifiableCredential,
        // we create a test VC
        // from a valid jwt then mock out the call to get the vcString, replacing with a jwt with
        // invalid signature
        var spyTestVc =
                spy(
                        VerifiableCredential.fromValidJwt(
                                MOCK_USER_ID, null, SignedJWT.parse(FAILED_DVLA_VC_WITH_CI_JWT)));
        when(spyTestVc.getVcString()).thenReturn(FAILED_DVLA_VC_WITH_CI_JWT_WITH_INVALID_SIGNATURE);

        var underTest = new CiMitService(mockConfigService);

        // Act/Assert
        assertThrows(
                CiPostMitigationsException.class,
                () ->
                        underTest.submitMitigatingVcList(
                                List.of(spyTestVc), MOCK_GOVUK_SIGNIN_ID, MOCK_IP_ADDRESS),
                FAILED_API_REQUEST);
    }

    @Pact(provider = "CiMitProvider", consumer = "IpvCoreBack")
    public RequestResponsePact postMitigationsInternalServerErrorReturns500(
            PactDslWithProvider builder) {
        var response = getFailedApiResponse("INTERNAL_SERVER_ERROR");

        return builder.given("mockIpAddress is the ip-address")
                .given("mockGovukSigninJourneyId is the govuk-signin-journey-id")
                .given("mockUserId is the user_id")
                .given("mockCimitComponentId is the issuer")
                .given("signed_jwts has only one encoded VC")
                .given("the encoded VC is from DCMAW-5477-AC1")
                .given("the VC has CI code TEST-CI-CODE")
                .uponReceiving("Request with valid JWTs but results in internal server error.")
                .path(POST_MITIGATIONS_ENDPOINT)
                .method("POST")
                .body(String.format("{\"signed_jwts\": [\"%s\"]}", FAILED_DVLA_VC_WITH_CI_JWT))
                .headers(
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
                                MOCK_USER_ID, null, SignedJWT.parse(FAILED_DVLA_VC_WITH_CI_JWT)));

        var underTest = new CiMitService(mockConfigService);

        // Act/Assert
        assertThrows(
                CiPostMitigationsException.class,
                () ->
                        underTest.submitMitigatingVcList(
                                List.of(testVc), MOCK_GOVUK_SIGNIN_ID, MOCK_IP_ADDRESS),
                FAILED_API_REQUEST);
    }

    private String getMockApiBaseUrl(MockServer mockServer) {
        return MOCK_SERVER_BASE_URL + mockServer.getPort();
    }

    private DslPart getFailedApiResponse(String reason) {
        return newJsonBody(
                        body -> {
                            body.stringValue("result", "fail");
                            body.stringValue("reason", reason);
                        })
                .build();
    }

    private static final String MOCK_IP_ADDRESS = "mockIpAddress";
    private static final String MOCK_USER_ID = "mockUserId";
    private static final String MOCK_GOVUK_SIGNIN_ID = "mockGovukSigninJourneyId";
    private static final String MOCK_SERVER_BASE_URL = "http://localhost:";
    private static final String TEST_ISSUER = "mockCimitComponentId";
    private static final String INVALID_JWT = "invalidJwt";
    private static final String INVALID_SIGNATURE = "invalidSignature";

    private static final String VALID_VC_HEADER =
            """
            {
              "alg": "ES256",
              "typ": "JWT"
            }
            """;

    // 2099-01-01 00:00:00 is 4070908800 in epoch seconds
    private static final String VALID_NO_CI_VC_BODY =
            """
            {
              "iss": "mockCimitComponentId",
              "sub": "mockUserId",
              "nbf": 1721899627,
              "exp": 4070908800,
              "vc": {
                "evidence": [
                  {
                    "contraIndicator": [],
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
    private static final String VALID_NO_CI_VC_SIGNATURE =
            "WbKckUsr2ubiqKkYqYJJyk9CfO2KQe3MldE0QE3Y8woAJZHcP_WpH6bSca_L6z8rP_P-E9J9dY1qxQjpb3r2Mg"; // pragma: allowlist secret
    private static final String VALID_NO_CI_VC_JWT =
            new PactJwtBuilder(VALID_VC_HEADER, VALID_NO_CI_VC_BODY, VALID_NO_CI_VC_SIGNATURE)
                    .buildJwt();

    // 2099-01-01 00:00:00 is 4070908800 in epoch seconds
    // 2010-01-01 00:00:00 is 1262304000 in epoch seconds
    private static final String VALID_CI_VC_BODY =
            """
            {
               "sub": "mockUserId",
               "iss": "mockCimitComponentId",
               "nbf": 1262304000,
               "iat": 4070908800,
               "exp": 4070908800,
               "vc": {
                 "type": [
                   "VerifiableCredential",
                   "SecurityCheckCredential"
                 ],
                 "evidence": [
                   {
                     "type": "SecurityCheck",
                     "contraIndicator": [
                       {
                         "code": "TEST-CI-CODE-1",
                         "issuers": [
                           "core"
                         ],
                         "issuanceDate": "2024-08-05T14:59:04.000Z",
                         "document": "idCard/FRE/852654",
                         "txn": [],
                         "mitigation": [
                           {
                             "mitigatingCredential": [
                               {
                                 "issuer": "core",
                                 "txn": "",
                                 "validFrom": "2024-08-05T14:59:05.000Z"
                               }
                             ],
                             "code": "TEST01"
                           }
                         ],
                         "incompleteMitigation": []
                       },
                       {
                         "code": "TEST-CI-CODE-2",
                         "issuers": [
                           "core"
                         ],
                         "issuanceDate": "2024-08-05T14:59:03.000Z",
                         "document": "passport/GBR/12345678",
                         "txn": [],
                         "mitigation": [
                           {
                             "mitigatingCredential": [
                               {
                                 "issuer": "core",
                                 "txn": "",
                                 "validFrom": "2024-08-05T14:59:05.000Z"
                               }
                             ],
                             "code": "TEST02"
                           }
                         ],
                         "incompleteMitigation": []
                       }
                     ]
                   }
                 ]
               }
             }
            """;

    // If we generate the signature in code it will be different each time, so we need to generate a
    // valid signature (using https://jwt.io works well) and record it here so the PACT file doesn't
    // change each time we run the tests.
    private static final String VALID_CI_VC_SIGNATURE =
            "5tmZS7VGkci8y4WLYzDcIcDqnbJ4deAtZa_OAEBSxYAFYJQxlxEj_XEUOXa0t-lbn-OjM-hIdaf9uW3DyBPzwQ"; // pragma: allowlist secret
    private static final String VALID_CI_VC_JWT =
            new PactJwtBuilder(VALID_VC_HEADER, VALID_CI_VC_BODY, VALID_CI_VC_SIGNATURE).buildJwt();

    // 2099-01-01 00:00:00 is 4070908800 in epoch seconds
    // From DCMAW-5477-AC1
    private static final String FAILED_DVLA_VC_WITH_CI_BODY =
            """
            {
              "iat": 1712228728,
              "iss": "mockCimitComponentId",
              "aud": "issuer",
              "sub": "mockUserId",
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

    // If we generate the signature in code it will be different each time, so we need to generate a
    // valid signature (using https://jwt.io works well) and record it here so the PACT file doesn't
    // change each time we run the tests.
    private static final String FAILED_DVLA_VC_WITH_CI_BODY_SIGNATURE =
            "PR1jYFN4AfDlkXBQQgnOqMDtTtS7QH_-xGn15lGXy1Nz8gdrhs0wEyIHf7xIPUA-j1ZqRiJF9kudmHfRwXOyqg"; // pragma: allowlist secret
    private static final String FAILED_DVLA_VC_WITH_CI_JWT =
            new PactJwtBuilder(
                            VALID_VC_HEADER,
                            FAILED_DVLA_VC_WITH_CI_BODY,
                            FAILED_DVLA_VC_WITH_CI_BODY_SIGNATURE)
                    .buildJwt();
    private static final String FAILED_DVLA_VC_WITH_CI_JWT_WITH_INVALID_SIGNATURE =
            new PactJwtBuilder(VALID_VC_HEADER, FAILED_DVLA_VC_WITH_CI_BODY, INVALID_SIGNATURE)
                    .buildJwt();

    // 2099-01-01 00:00:00 is 4070908800 in epoch seconds
    // From DCMAW-5477-AC1
    private static final String DVLA_VC_WITH_CI_AND_INVALID_ISSUER =
            """
            {
              "iat": 1712228728,
              "iss": "invalidIssuer",
              "aud": "issuer",
              "sub": "mockUserId",
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

    // If we generate the signature in code it will be different each time, so we need to generate a
    // valid signature (using https://jwt.io works well) and record it here so the PACT file doesn't
    // change each time we run the tests.
    private static final String DVLA_VC_WITH_CI_AND_INVALID_ISSUER_SIGNATURE =
            "8c6iIjlh7JipvbhkOBesiumnFp_EcZpAkBuOpVxNIdAO68ZUmxMYW4MpVi7jz0-dbMGOgKHROIPQZ4yw-wsa_Q"; // pragma: allowlist secret
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
              "iss": "mockCimitComponentId",
              "aud": "issuer",
              "sub": "mockUserId",
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

    // If we generate the signature in code it will be different each time, so we need to generate a
    // valid signature (using https://jwt.io works well) and record it here so the PACT file doesn't
    // change each time we run the tests.
    private static final String DVLA_VC_WITH_CI_AND_INVALID_CI_CODE_SIGNATURE =
            "YpmpMHYX855TlSObxSVJex-35r8GWFLFWS1UZ3uPndmK5kIRZOT5wiiE_dXaHmPWlPa0EP7z2NrYs2NLLzrTkA"; // pragma: allowlist secret
    private static final String DVLA_VC_WITH_CI_AND_INVALID_CI_CODE_JWT =
            new PactJwtBuilder(
                            VALID_VC_HEADER,
                            DVLA_VC_WITH_CI_AND_INVALID_CI_CODE,
                            DVLA_VC_WITH_CI_AND_INVALID_CI_CODE_SIGNATURE)
                    .buildJwt();
}
