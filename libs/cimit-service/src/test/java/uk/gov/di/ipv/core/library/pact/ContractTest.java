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
import uk.gov.di.ipv.core.library.cimit.exception.CiPutException;
import uk.gov.di.ipv.core.library.cimit.exception.CiRetrievalException;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.exceptions.CredentialParseException;
import uk.gov.di.ipv.core.library.pacttesthelpers.PactJwtBuilder;
import uk.gov.di.ipv.core.library.service.CiMitService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.model.SecurityCheck;
import uk.gov.di.model.SecurityCheckCredential;

import java.io.IOException;
import java.net.http.HttpRequest;
import java.text.ParseException;

import static au.com.dius.pact.consumer.dsl.LambdaDsl.newJsonBody;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
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
            MockServer mockServer) throws CiRetrievalException {
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
    public RequestResponsePact successfullyReceivesContraIndicators(PactDslWithProvider builder) {
        var responseForPostCi = newJsonBody(body -> body.stringValue("result", "success")).build();

        return builder.given("mockApiKey is a valid api key")
                .given("mockUserId is the user_id")
                .uponReceiving(
                        "Request for contra-indicators for specific user with existing contra-indicators.")
                .path(POST_CI_ENDPOINT)
                .method("POST")
                .body(String.format("{\"signed_jwt\": \"%s\"}", VALID_SIGNED_CI_VC_JWT))
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
    @PactTestFor(pactMethod = "successfullyReceivesContraIndicators")
    void successfullyPostCis_whenCalledWithSignedJwtAgainstCimiApi(MockServer mockServer)
            throws CiPutException, ParseException, CredentialParseException, IOException,
                    InterruptedException {
        // Arrange
        when(mockConfigService.getParameter(CIMIT_API_BASE_URL))
                .thenReturn(getMockApiBaseUrl(mockServer));
        var underTest = new CiMitService(mockConfigService);

        var testVc =
                VerifiableCredential.fromValidJwt(
                        MOCK_USER_ID, null, SignedJWT.parse(VALID_SIGNED_CI_VC_JWT));

        // Act
        underTest.submitVC(testVc, MOCK_GOVUK_SIGNIN_ID, MOCK_IP_ADDRESS);

        // Assert
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
    private static final String MOCK_GOVUK_SIGNIN_ID = "mockGovukSigningId";
    private static final String MOCK_API_KEY = "mockApiKey"; // pragma: allowlist secret
    private static final String MOCK_SERVER_BASE_URL = "http://localhost:";
    private static final String TEST_ISSUER = "mockCimitComponentId";

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

    private static final String VALID_SIGNED_CI_VC_JWT =
            "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJtb2NrVXNlcklkIiwibmJmIjoxMjYyMzA0MDAwLCJpc3MiOiJtb2NrQ2ltaXRDb21wb25lbnRJZCIsImV4cCI6MjAwNTMwMzE2OCwiaWF0IjoxMjYyMzA0MDAwLCJ2YyI6eyJldmlkZW5jZSI6W3siY29udHJhSW5kaWNhdG9yIjpbeyJtaXRpZ2F0aW9uIjpbeyJtaXRpZ2F0aW5nQ3JlZGVudGlhbCI6W3sidmFsaWRGcm9tIjoiMjAxMC0wMS0wMVQwMDowMDowMC4wMDBaIiwidHhuIjoiZ2hpaiIsImlkIjoidXJuOnV1aWQ6ZjgxZDRmYWUtN2RlYy0xMWQwLWE3NjUtMDBhMGM5MWU2YmY2IiwiaXNzdWVyIjoiaHR0cHM6Ly9jcmVkZW50aWFsLWlzc3Vlci5leGFtcGxlLyJ9XSwiY29kZSI6InNvbWUtY29kZSJ9XSwiY29kZSI6InNvbWUtY29kZSIsImlzc3VlcnMiOlsiaHR0cHM6Ly9pc3N1aW5nLWNyaS5leGFtcGxlIl0sImluY29tcGxldGVNaXRpZ2F0aW9uIjpbeyJtaXRpZ2F0aW5nQ3JlZGVudGlhbCI6W3sidmFsaWRGcm9tIjoiMjAxMC0wMS0wMVQwMDowMDowMC4wMDBaIiwidHhuIjoiY2RlZWYiLCJpZCI6InVybjp1dWlkOmY1YzlmZjQwLTFkY2QtNGE4Yi1iZjkyLTk0NTYwNDdjMTMyZiIsImlzc3VlciI6Imh0dHBzOi8vYW5vdGhlci1jcmVkZW50aWFsLWlzc3Vlci5leGFtcGxlLyJ9XSwiY29kZSI6InNvbWUtY29kZSJ9XSwiaXNzdWFuY2VEYXRlIjoiMjAyMi0wOS0yMFQxNTo1NDo1MC4wMDBaIiwiZG9jdW1lbnQiOiJwYXNzcG9ydC9HQlIvODI0MTU5MTIxIiwidHhuIjpbImFiY2RlZiJdfV0sInR4biI6WyJma2ZrZCJdLCJ0eXBlIjoiU2VjdXJpdHlDaGVjayJ9XSwidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsIlNlY3VyaXR5Q2hlY2tDcmVkZW50aWFsIl19fQ.AEt6i6mZ1mLcOVuSDdKISHcUzKSQ68q0ySPIABzbYM1cJ4Ir8naySMVJxasIaI72Uaw96UEzKPXhKg9IM2IVDw"; // pragma: allowlist secret
}
