package uk.gov.di.ipv.core.library.cimit.pact;

import au.com.dius.pact.consumer.MockServer;
import au.com.dius.pact.consumer.dsl.DslPart;
import au.com.dius.pact.consumer.dsl.PactDslRequestBase;
import au.com.dius.pact.consumer.dsl.PactDslWithProvider;
import au.com.dius.pact.consumer.junit.MockServerConfig;
import au.com.dius.pact.consumer.junit5.PactConsumerTestExt;
import au.com.dius.pact.consumer.junit5.PactTestFor;
import au.com.dius.pact.core.model.RequestResponsePact;
import au.com.dius.pact.core.model.annotations.Pact;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.cimit.exception.CiPostMitigationsException;
import uk.gov.di.ipv.core.library.cimit.exception.CiPutException;
import uk.gov.di.ipv.core.library.cimit.exception.CiRetrievalException;
import uk.gov.di.ipv.core.library.cimit.service.CimitService;
import uk.gov.di.ipv.core.library.config.domain.CimitConfig;
import uk.gov.di.ipv.core.library.config.domain.Config;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.exceptions.CredentialParseException;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.testhelpers.pact.PactJwtBuilder;
import uk.gov.di.model.SecurityCheck;
import uk.gov.di.model.SecurityCheckCredential;

import java.net.URI;
import java.text.ParseException;
import java.util.List;
import java.util.Map;

import static au.com.dius.pact.consumer.dsl.LambdaDsl.newJsonBody;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.spy;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.cimit.service.CimitService.FAILED_API_REQUEST;
import static uk.gov.di.ipv.core.library.cimit.service.CimitService.GET_VCS_ENDPOINT;
import static uk.gov.di.ipv.core.library.cimit.service.CimitService.GOVUK_SIGNIN_JOURNEY_ID_HEADER;
import static uk.gov.di.ipv.core.library.cimit.service.CimitService.IP_ADDRESS_HEADER;
import static uk.gov.di.ipv.core.library.cimit.service.CimitService.POST_CI_ENDPOINT;
import static uk.gov.di.ipv.core.library.cimit.service.CimitService.POST_MITIGATIONS_ENDPOINT;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.EC_PRIVATE_KEY_JWK;

@ExtendWith(PactConsumerTestExt.class)
@ExtendWith(MockitoExtension.class)
@PactTestFor(providerName = "CiMitProvider")
@MockServerConfig(hostInterface = "localhost")
class ContractTest {
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    @Mock ConfigService mockConfigService;
    @Mock Config mockConfig;
    @Mock CimitConfig mockCimitConfig;

    @BeforeEach
    void setUp() {
        when(mockConfigService.getConfiguration()).thenReturn(mockConfig);
        when(mockConfig.getCimit()).thenReturn(mockCimitConfig);
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
    void fetchContraIndicators_whenCalledWithUserIdAgainstCimitApi_receivesContraIndicators(
            MockServer mockServer) throws CiRetrievalException {

        when(mockCimitConfig.getComponentId()).thenReturn(URI.create(TEST_ISSUER));
        when(mockCimitConfig.getSigningKey()).thenReturn(EC_PRIVATE_KEY_JWK);
        when(mockCimitConfig.getApiBaseUrl()).thenReturn(URI.create(getMockApiBaseUrl(mockServer)));

        var underTest = new CimitService(mockConfigService);
        var ipvSessionItem =
                IpvSessionItem.builder().securityCheckCredential(VALID_CI_VC_JWT).build();

        // Act
        var contraIndicatorVc =
                underTest.fetchContraIndicatorsVc(
                        MOCK_USER_ID, MOCK_GOVUK_SIGNIN_ID, MOCK_IP_ADDRESS, ipvSessionItem);

        // Assert
        assertEquals(MOCK_USER_ID, contraIndicatorVc.getUserId());
        assertInstanceOf(SecurityCheckCredential.class, contraIndicatorVc.getCredential());

        var securityCheckCredential = (SecurityCheckCredential) contraIndicatorVc.getCredential();
        var evidence = (SecurityCheck) securityCheckCredential.getEvidence().get(0);

        assertEquals(2, evidence.getContraIndicator().size());
        assertEquals("idCard/FRE/852654", evidence.getContraIndicator().get(0).getDocument());
        assertEquals("TEST-CI-CODE-1", evidence.getContraIndicator().get(0).getCode());
        assertEquals(1, evidence.getContraIndicator().get(0).getMitigation().size());
        assertEquals(
                "TEST01", evidence.getContraIndicator().get(0).getMitigation().get(0).getCode());

        assertEquals("passport/GBR/12345678", evidence.getContraIndicator().get(1).getDocument());
        assertEquals("TEST-CI-CODE-2", evidence.getContraIndicator().get(1).getCode());
        assertEquals(1, evidence.getContraIndicator().get(1).getMitigation().size());
        assertEquals(
                "TEST02", evidence.getContraIndicator().get(1).getMitigation().get(0).getCode());
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
    void fetchContraIndicators_whenCalledWithUserIdAgainstCimitApi_receivesEmptyContraIndicators(
            MockServer mockServer) throws CiRetrievalException {
        // Arrange
        when(mockCimitConfig.getComponentId()).thenReturn(URI.create(TEST_ISSUER));
        when(mockCimitConfig.getSigningKey()).thenReturn(EC_PRIVATE_KEY_JWK);
        when(mockConfigService.getConfiguration().getCimit().getApiBaseUrl())
                .thenReturn(URI.create(getMockApiBaseUrl(mockServer)));
        var underTest = new CimitService(mockConfigService);
        var ipvSessionItem =
                IpvSessionItem.builder().securityCheckCredential(VALID_NO_CI_VC_JWT).build();

        // Act
        var contraIndicatorsVc =
                underTest.fetchContraIndicatorsVc(
                        MOCK_USER_ID, MOCK_GOVUK_SIGNIN_ID, MOCK_IP_ADDRESS, ipvSessionItem);

        // Assert
        assertEquals(MOCK_USER_ID, contraIndicatorsVc.getUserId());
        assertInstanceOf(SecurityCheckCredential.class, contraIndicatorsVc.getCredential());

        var securityCheckCredential = (SecurityCheckCredential) contraIndicatorsVc.getCredential();
        var evidence = (SecurityCheck) securityCheckCredential.getEvidence().get(0);

        assertEquals(0, evidence.getContraIndicator().size());
    }

    @Pact(provider = "CiMitProvider", consumer = "IpvCoreBack")
    public RequestResponsePact postCiSuccessfullyPostsContraIndicator(PactDslWithProvider builder)
            throws JsonProcessingException {
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
                .body(
                        OBJECT_MAPPER.writeValueAsString(
                                Map.of("signed_jwt", FAILED_DVLA_VC_WITH_CI_JWT)))
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
    void successfullyPostCis_whenCalledWithSignedJwtAgainstCimitApi_returns200(
            MockServer mockServer) throws ParseException, CredentialParseException {
        // Arrange
        when(mockConfigService.getConfiguration().getCimit().getApiBaseUrl())
                .thenReturn(URI.create(getMockApiBaseUrl(mockServer)));

        var testVc =
                VerifiableCredential.fromValidJwt(
                        MOCK_USER_ID, null, SignedJWT.parse(FAILED_DVLA_VC_WITH_CI_JWT));

        var underTest = new CimitService(mockConfigService);

        // Act
        assertDoesNotThrow(() -> underTest.submitVC(testVc, MOCK_GOVUK_SIGNIN_ID, MOCK_IP_ADDRESS));
    }

    @Pact(provider = "CiMitProvider", consumer = "IpvCoreBack")
    public RequestResponsePact postCiInvalidIssuerReturns400(PactDslWithProvider builder)
            throws JsonProcessingException {
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
                .body(
                        OBJECT_MAPPER.writeValueAsString(
                                Map.of("signed_jwt", DVLA_VC_WITH_CI_AND_INVALID_ISSUER_JWT)))
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
    void failsToPostCis_whenCalledWithInvalidIssuerAgainstCimitApi_returns400(MockServer mockServer)
            throws ParseException, CredentialParseException {
        // Arrange
        when(mockConfigService.getConfiguration().getCimit().getApiBaseUrl())
                .thenReturn(URI.create(getMockApiBaseUrl(mockServer)));

        var testVc =
                spy(
                        VerifiableCredential.fromValidJwt(
                                MOCK_USER_ID,
                                null,
                                SignedJWT.parse(DVLA_VC_WITH_CI_AND_INVALID_ISSUER_JWT)));

        var underTest = new CimitService(mockConfigService);

        // Act/Assert
        assertThrows(
                CiPutException.class,
                () -> underTest.submitVC(testVc, MOCK_GOVUK_SIGNIN_ID, MOCK_IP_ADDRESS),
                FAILED_API_REQUEST);
    }

    @Pact(provider = "CiMitProvider", consumer = "IpvCoreBack")
    public RequestResponsePact postMitigationsSuccessfullyReceivesMitigations(
            PactDslWithProvider builder) throws JsonProcessingException {
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
                .body(
                        OBJECT_MAPPER.writeValueAsString(
                                Map.of("signed_jwts", List.of(FAILED_DVLA_VC_WITH_CI_JWT))))
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
    @PactTestFor(pactMethod = "postMitigationsSuccessfullyReceivesMitigations")
    void successfullyPostsMitigations_whenCalledWithSignedJwtAgainstCimitApi_returns200(
            MockServer mockServer) throws ParseException, CredentialParseException {
        // Arrange
        when(mockConfigService.getConfiguration().getCimit().getApiBaseUrl())
                .thenReturn(URI.create(getMockApiBaseUrl(mockServer)));

        var testVc =
                VerifiableCredential.fromValidJwt(
                        MOCK_USER_ID, null, SignedJWT.parse(FAILED_DVLA_VC_WITH_CI_JWT));

        var underTest = new CimitService(mockConfigService);

        // Act
        assertDoesNotThrow(
                () ->
                        underTest.submitMitigatingVcList(
                                List.of(testVc), MOCK_GOVUK_SIGNIN_ID, MOCK_IP_ADDRESS));
    }

    @Pact(provider = "CiMitProvider", consumer = "IpvCoreBack")
    public RequestResponsePact postMitigationsInvalidIssuerReturns400(PactDslWithProvider builder)
            throws JsonProcessingException {
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
                        OBJECT_MAPPER.writeValueAsString(
                                Map.of(
                                        "signed_jwts",
                                        List.of(DVLA_VC_WITH_CI_AND_INVALID_ISSUER_JWT))))
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
    void failsToPostMitigations_whenCalledWithInvalidIssuerAgainstCimitApi_returns400(
            MockServer mockServer) throws ParseException, CredentialParseException {
        // Arrange
        when(mockConfigService.getConfiguration().getCimit().getApiBaseUrl())
                .thenReturn(URI.create(getMockApiBaseUrl(mockServer)));

        var testVc =
                VerifiableCredential.fromValidJwt(
                        MOCK_USER_ID,
                        null,
                        SignedJWT.parse(DVLA_VC_WITH_CI_AND_INVALID_ISSUER_JWT));

        var underTest = new CimitService(mockConfigService);

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
              "nbf": 1262304000,
              "iat": 1262304000,
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
            "ZSPpIHn7ahuqppckpDg4i48Ei_J7eZLbCMFo_0NUIvQeFF2ZbdoR6-GZhbFqHnfBr5N9o75Epom_M6CKJgrIXw"; // pragma: allowlist secret
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
               "iat": 1262304000,
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
            "HjMYSU0SWgo_Eo073HH28fr6NJnkzYmi6MR9Qan4R8kvl4NUS0j_-F1y01_R4hsrbDys2-NWP1s1gZ5qA8SSMQ"; // pragma: allowlist secret
    private static final String VALID_CI_VC_JWT =
            new PactJwtBuilder(VALID_VC_HEADER, VALID_CI_VC_BODY, VALID_CI_VC_SIGNATURE).buildJwt();

    // 2099-01-01 00:00:00 is 4070908800 in epoch seconds
    private static final String FAILED_DVLA_VC_WITH_CI_BODY =
            """
            {
              "iat": 1262304000,
              "iss": "mockCimitComponentId",
              "aud": "issuer",
              "sub": "mockUserId",
              "nbf": 1262304000,
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
            "oscpEvGkT18T6SzlS7CKk601j-Yse2LCIqkU_q_5Tz2olmSk-YF2rdK6V6_D8sXE3XSPi4Hi_aAhWTB5Y2naKg"; // pragma: allowlist secret
    private static final String FAILED_DVLA_VC_WITH_CI_JWT =
            new PactJwtBuilder(
                            VALID_VC_HEADER,
                            FAILED_DVLA_VC_WITH_CI_BODY,
                            FAILED_DVLA_VC_WITH_CI_BODY_SIGNATURE)
                    .buildJwt();

    // 2099-01-01 00:00:00 is 4070908800 in epoch seconds
    private static final String DVLA_VC_WITH_CI_AND_INVALID_ISSUER =
            """
            {
              "iat": 1262304000,
              "iss": "invalidIssuer",
              "aud": "issuer",
              "sub": "mockUserId",
              "nbf": 1262304000,
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
            "ypABJzp8XFkHbhl9dnkP0L8Xp3k-MI5QD-kw0gjSHJWc4OJccEAWkq2nwbykX9I8nb-jNcqoNX5fkcQaQJ9hEg"; // pragma: allowlist secret
    private static final String DVLA_VC_WITH_CI_AND_INVALID_ISSUER_JWT =
            new PactJwtBuilder(
                            VALID_VC_HEADER,
                            DVLA_VC_WITH_CI_AND_INVALID_ISSUER,
                            DVLA_VC_WITH_CI_AND_INVALID_ISSUER_SIGNATURE)
                    .buildJwt();
}
