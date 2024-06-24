package uk.gov.di.ipv.core.processcricallback.pact.experianKbvCri;

import au.com.dius.pact.consumer.MockServer;
import au.com.dius.pact.consumer.dsl.PactDslWithProvider;
import au.com.dius.pact.consumer.junit.MockServerConfig;
import au.com.dius.pact.consumer.junit5.PactConsumerTestExt;
import au.com.dius.pact.consumer.junit5.PactTestFor;
import au.com.dius.pact.core.model.RequestResponsePact;
import au.com.dius.pact.core.model.annotations.Pact;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.token.AccessTokenType;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
import uk.gov.di.ipv.core.library.criapiservice.CriApiService;
import uk.gov.di.ipv.core.library.criapiservice.exception.CriApiException;
import uk.gov.di.ipv.core.library.domain.ContraIndicatorConfig;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants;
import uk.gov.di.ipv.core.library.dto.CriCallbackRequest;
import uk.gov.di.ipv.core.library.dto.OauthCriConfig;
import uk.gov.di.ipv.core.library.exceptions.VerifiableCredentialException;
import uk.gov.di.ipv.core.library.helpers.FixedTimeJWTClaimsVerifier;
import uk.gov.di.ipv.core.library.helpers.SecureTokenHelper;
import uk.gov.di.ipv.core.library.kmses256signer.KmsEs256SignerFactory;
import uk.gov.di.ipv.core.library.pacttesthelpers.PactJwtIgnoreSignatureBodyBuilder;
import uk.gov.di.ipv.core.library.persistence.item.CriOAuthSessionItem;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.verifiablecredential.validator.VerifiableCredentialValidator;

import java.net.URI;
import java.net.URISyntaxException;
import java.sql.Date;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static au.com.dius.pact.consumer.dsl.LambdaDsl.newJsonBody;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.greaterThan;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.domain.Cri.EXPERIAN_KBV;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.EC_PRIVATE_KEY_JWK;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.EXAMPLE_GENERATED_SECURE_TOKEN;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.RSA_ENCRYPTION_PUBLIC_JWK;

@ExtendWith(PactConsumerTestExt.class)
@ExtendWith(MockitoExtension.class)
@PactTestFor(providerName = "ExperianKbvCriProvider")
@MockServerConfig(hostInterface = "localhost")
class ContractTest {
    private static final String TEST_USER = "test-subject";
    private static final String TEST_ISSUER = "dummyExperianKbvComponentId";
    private static final String IPV_CORE_CLIENT_ID = "ipv-core";
    private static final String PRIVATE_API_KEY = "dummyApiKey";
    private static final Clock CURRENT_TIME =
            Clock.fixed(Instant.parse("2099-01-01T00:00:00.00Z"), ZoneOffset.UTC);

    private static final ObjectMapper objectMapper = new ObjectMapper();

    private static final String CLIENT_ASSERTION_HEADER = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9";
    private static final String CLIENT_ASSERTION_BODY =
            "eyJpc3MiOiJpcHYtY29yZSIsInN1YiI6Imlwdi1jb3JlIiwiYXVkIjoiZHVtbXlFeHBlcmlhbktidkNvbXBvbmVudElkIiwiZXhwIjo0MDcwOTA5NzAwLCJqdGkiOiJTY25GNGRHWHRoWllYU181azg1T2JFb1NVMDRXLUgzcWFfcDZucHYyWlVZIn0"; // pragma: allowlist secret
    // Signature generated using JWT.io
    private static final String CLIENT_ASSERTION_SIGNATURE =
            "aJOEpvnBRpaptv_2T7L5aCzhTdvlNaGNh3uwuK1f5cC9he9izuIr60s2_Y6-DIPEWLE0_L6ckgdIsy9G7yj8jA"; // pragma: allowlist secret
    // We hardcode the VC headers and bodies like this so that it is easy to update them from JSON
    // sent by the CRI team
    private static final String VALID_VC_HEADER =
            """
            {
              "alg": "ES256",
              "typ": "JWT"
            }
            """;

    private static final String VALID_VC_BODY =
            """
                {
                  "iss": "dummyExperianKbvComponentId",
                  "sub": "test-subject",
                  "nbf": 4070908800,
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
                              "type": "GivenName",
                              "value": "Mary"
                            },
                            {
                              "type": "FamilyName",
                              "value": "Watson"
                            }
                          ]
                        }
                      ],
                      "birthDate": [
                        {
                          "value": "1932-02-25"
                        }
                      ],
                      "address": [
                        {
                          "uprn": "10022812929",
                          "organisationName": "FINCH GROUP",
                          "subBuildingName": "UNIT 2B",
                          "buildingNumber": "16",
                          "buildingName": "COY POND BUSINESS PARK",
                          "dependentStreetName": "KINGS PARK",
                          "streetName": "BIG STREET",
                          "doubleDependentAddressLocality": "SOME DISTRICT",
                          "dependentAddressLocality": "LONG EATON",
                          "addressLocality": "GREAT MISSENDEN",
                          "postalCode": "HP16 0AL",
                          "addressCountry": "GB"
                        }
                      ]
                    },
                "evidence": [
                    {
                      "checkDetails": [
                        {
                          "checkMethod": "kbv",
                          "kbvQuality": 2,
                          "kbvResponseMode": "multiple_choice"
                        },
                        {
                          "checkMethod": "kbv",
                          "kbvQuality": 2,
                          "kbvResponseMode": "multiple_choice"
                        },
                        {
                          "checkMethod": "kbv",
                          "kbvQuality": 1,
                          "kbvResponseMode": "multiple_choice"
                        }
                      ],
                      "verificationScore": 2,
                      "txn": "dummyTxn",
                      "type": "IdentityCheck"
                    }]
                  }
                }
                """;

    private static final String VALID_THIN_FILE_VC_BODY =
            """
            {
               "iss": "dummyExperianKbvComponentId",
               "sub": "test-subject",
               "nbf": 4070908800,
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
                           "type": "GivenName",
                           "value": "Mary"
                         },
                         {
                           "type": "FamilyName",
                           "value": "Watson"
                         }
                       ]
                     }
                   ],
                   "birthDate": [
                     {
                       "value": "1932-02-25"
                     }
                   ],
               "address": [
                     {
                       "uprn": "10022812929",
                       "organisationName": "FINCH GROUP",
                       "subBuildingName": "UNIT 2B",
                       "buildingNumber": "16",
                       "buildingName": "COY POND BUSINESS PARK",
                       "dependentStreetName": "KINGS PARK",
                       "streetName": "BIG STREET",
                       "doubleDependentAddressLocality": "SOME DISTRICT",
                       "dependentAddressLocality": "LONG EATON",
                       "addressLocality": "GREAT MISSENDEN",
                       "postalCode": "HP16 0AL",
                       "addressCountry": "GB"
                     }
                   ]
             },
             "evidence": [
                 {
                   "type": "IdentityCheck",
                   "txn": "dummyTxn",
                   "verificationScore": 0,
                   "checkDetails": [
                     {
                       "checkMethod": "kbv",
                       "kbvQuality": 3,
                       "kbvResponseMode": "multiple_choice"
                     },
                     {
                       "checkMethod": "kbv",
                       "kbvQuality": 2,
                       "kbvResponseMode": "multiple_choice"
                     }
                   ]
                 }
               ]
               }
             }
            """;

    private static final String FAILED_VC_BODY =
            """
            {
              "iss": "dummyExperianKbvComponentId",
              "sub": "test-subject",
              "nbf": 4070908800,
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
                          "type": "GivenName",
                          "value": "Mary"
                        },
                        {
                          "type": "FamilyName",
                          "value": "Watson"
                        }
                      ]
                    }
                  ],
                  "birthDate": [
                    {
                      "value": "1932-02-25"
                    }
                  ],
                  "address": [
                        {
                          "uprn": "10022812929",
                          "organisationName": "FINCH GROUP",
                          "subBuildingName": "UNIT 2B",
                          "buildingNumber": "16",
                          "buildingName": "COY POND BUSINESS PARK",
                          "dependentStreetName": "KINGS PARK",
                          "streetName": "BIG STREET",
                          "doubleDependentAddressLocality": "SOME DISTRICT",
                          "dependentAddressLocality": "LONG EATON",
                          "addressLocality": "GREAT MISSENDEN",
                          "postalCode": "HP16 0AL",
                          "addressCountry": "GB"
                        }
                      ]
                },
                "evidence": [
                    {
                        "type": "IdentityCheck",
                        "txn": "dummyTxn",
                        "verificationScore": 0,
                        "checkDetails": [
                            {
                                "checkMethod": "kbv",
                                "kbvQuality": 3,
                                "kbvResponseMode": "multiple_choice"
                            }
                        ],
                        "failedCheckDetails": [
                            {
                                "kbvResponseMode": "multiple_choice",
                                "checkMethod": "kbv"
                            },
                            {
                                "kbvResponseMode": "multiple_choice",
                                "checkMethod": "kbv"
                            }],
                            "ci": ["A03"]
                    }
                  ]
              }
            }
            """;

    // If we generate the signature in code it will be different each time, so we need to generate a
    // valid signature (using https://jwt.io works well) and record it here so the PACT file doesn't
    // change each time we run the tests.
    private static final String VALID_VC_SIGNATURE =
            "ar6tKitq-mO854GDVKKXMfNFaYUOeMY2SZeqgByDRFGhno2dae4VR3AE2yFx798y6vUbTeFfcZ9jsRs37lZ65A"; // pragma: allowlist secret

    private static final String VALID_THIN_FILE_VC_SIGNATURE =
            "GIJxbgGgu57fydU-7Qnu7-9PN7QdOK4Lg_TvP7vSHvhhSA16k8dvbfiQpT45fZ-Hs9CrOzGCe3jCgaQAlAnOQA"; // pragma: allowlist secret

    private static final String FAILED_VC_SIGNATURE =
            "7sZ4VzYx1Sa-dtopqcEWptXoH2YVdbsyO41bujquBmujbovRI6F9QJAEt5eYOGTyJ-sro_6yfpEWR14uxLAycg"; // pragma: allowlist secret

    @Mock private ConfigService mockConfigService;
    @Mock private KmsEs256SignerFactory mockKmsEs256SignerFactory;
    @Mock private JWSSigner mockSigner;
    @Mock private SecureTokenHelper mockSecureTokenHelper;

    @Pact(provider = "ExperianKbvCriProvider", consumer = "IpvCoreBack")
    public RequestResponsePact validRequestReturnsValidAccessToken(PactDslWithProvider builder) {
        return builder.given("dummyAuthCode is a valid authorization code")
                .given("dummyApiKey is a valid api key")
                .given("dummyExperianKbvComponentId is the experianKbv CRI component ID")
                .given(
                        "ExperianKbv CRI uses CORE_BACK_SIGNING_PRIVATE_KEY_JWK to validate core signatures")
                .uponReceiving("Valid auth code")
                .path("/token")
                .method("POST")
                .body(
                        "client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer&code=dummyAuthCode&grant_type=authorization_code&redirect_uri=https%3A%2F%2Fidentity.staging.account.gov.uk%2Fcredential-issuer%2Fcallback%3Fid%3Dkbv&client_assertion=" // pragma: allowlist secret
                                + CLIENT_ASSERTION_HEADER
                                + "."
                                + CLIENT_ASSERTION_BODY
                                + "."
                                + CLIENT_ASSERTION_SIGNATURE)
                .headers(
                        "x-api-key",
                        PRIVATE_API_KEY,
                        "Content-Type",
                        "application/x-www-form-urlencoded; charset=UTF-8")
                .willRespondWith()
                .status(200)
                .body(
                        newJsonBody(
                                        body -> {
                                            body.stringType("access_token");
                                            body.stringValue("token_type", "Bearer");
                                            body.integerType("expires_in");
                                        })
                                .build())
                .toPact();
    }

    @Test
    @PactTestFor(pactMethod = "validRequestReturnsValidAccessToken")
    void fetchAccessToken_whenCalledAgainstExperianKbvCri_retrievesAValidAccessToken(
            MockServer mockServer) throws URISyntaxException, JOSEException, CriApiException {
        // Arrange
        var credentialIssuerConfig = getMockCredentialIssuerConfig(mockServer);

        when(mockConfigService.getSsmParameter(ConfigurationVariable.JWT_TTL_SECONDS))
                .thenReturn("900");
        when(mockConfigService.getOauthCriConfig(any())).thenReturn(credentialIssuerConfig);
        when(mockConfigService.getCriPrivateApiKey(any())).thenReturn(PRIVATE_API_KEY);

        // Signature generated by jwt.io by debugging the test and getting the client assertion JWT
        // generated by the test as mocking out the AWSKMS class inside the real signer would be
        // painful.
        when(mockKmsEs256SignerFactory.getSigner(any())).thenReturn(mockSigner);
        when(mockSigner.sign(any(), any())).thenReturn(new Base64URL(CLIENT_ASSERTION_SIGNATURE));
        when(mockSigner.supportedJWSAlgorithms()).thenReturn(Set.of(JWSAlgorithm.ES256));
        when(mockSecureTokenHelper.generate()).thenReturn(EXAMPLE_GENERATED_SECURE_TOKEN);

        // We need to generate a fixed request, so we set the secure token and expiry to constant
        // values.
        var underTest =
                new CriApiService(
                        mockConfigService,
                        mockKmsEs256SignerFactory,
                        mockSecureTokenHelper,
                        CURRENT_TIME);

        // Act
        BearerAccessToken accessToken =
                underTest.fetchAccessToken(
                        getCallbackRequest("dummyAuthCode"), getCriOAuthSessionItem());
        // Assert
        assertThat(accessToken.getType(), is(AccessTokenType.BEARER));
        assertThat(accessToken.getValue(), notNullValue());
        assertThat(accessToken.getLifetime(), greaterThan(0L));
    }

    @Pact(provider = "ExperianKbvCriProvider", consumer = "IpvCoreBack")
    public RequestResponsePact invalidAuthCodeRequestReturns400(PactDslWithProvider builder) {
        return builder.given("dummyInvalidAuthCode is an invalid authorization code")
                .given("dummyApiKey is a valid api key")
                .given("dummyExperianKbvComponentId is the experianKbv CRI component ID")
                .given(
                        "ExperianKbv CRI uses CORE_BACK_SIGNING_PRIVATE_KEY_JWK to validate core signatures")
                .uponReceiving("Invalid authorization code")
                .path("/token")
                .method("POST")
                .body(
                        "client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer&code=dummyInvalidAuthCode&grant_type=authorization_code&redirect_uri=https%3A%2F%2Fidentity.staging.account.gov.uk%2Fcredential-issuer%2Fcallback%3Fid%3Dkbv&client_assertion="
                                + CLIENT_ASSERTION_HEADER
                                + "."
                                + CLIENT_ASSERTION_BODY
                                + "."
                                + CLIENT_ASSERTION_SIGNATURE)
                .headers(
                        "x-api-key",
                        PRIVATE_API_KEY,
                        "Content-Type",
                        "application/x-www-form-urlencoded; charset=UTF-8")
                .willRespondWith()
                .status(400)
                .toPact();
    }

    @Test
    @PactTestFor(pactMethod = "invalidAuthCodeRequestReturns400")
    void fetchAccessToken_whenCalledAgainstExperianKbvCriWithInvalidAuthCode_throwsAnException(
            MockServer mockServer) throws URISyntaxException, JOSEException {

        // Arrange
        var credentialIssuerConfig = getMockCredentialIssuerConfig(mockServer);

        when(mockConfigService.getSsmParameter(ConfigurationVariable.JWT_TTL_SECONDS))
                .thenReturn("900");
        when(mockConfigService.getOauthCriConfig(any())).thenReturn(credentialIssuerConfig);
        when(mockConfigService.getCriPrivateApiKey(any())).thenReturn(PRIVATE_API_KEY);

        // Signature generated by jwt.io by debugging the test and getting the client assertion
        // JWT
        // generated by the test as mocking out the AWSKMS class inside the real signer would be
        // painful.
        when(mockKmsEs256SignerFactory.getSigner(any())).thenReturn(mockSigner);
        when(mockSigner.sign(any(), any())).thenReturn(new Base64URL(CLIENT_ASSERTION_SIGNATURE));
        when(mockSigner.supportedJWSAlgorithms()).thenReturn(Set.of(JWSAlgorithm.ES256));
        when(mockSecureTokenHelper.generate()).thenReturn(EXAMPLE_GENERATED_SECURE_TOKEN);

        // We need to generate a fixed request, so we set the secure token and expiry to
        // constant
        // values.
        var underTest =
                new CriApiService(
                        mockConfigService,
                        mockKmsEs256SignerFactory,
                        mockSecureTokenHelper,
                        CURRENT_TIME);

        // Act
        CriApiException exception =
                assertThrows(
                        CriApiException.class,
                        () ->
                                underTest.fetchAccessToken(
                                        getCallbackRequest("dummyInvalidAuthCode"),
                                        getCriOAuthSessionItem()));

        // Assert
        assertEquals("Invalid token request", exception.getErrorResponse().getMessage());
        assertEquals(400, exception.getHttpStatusCode());
    }

    @Pact(provider = "ExperianKbvCriProvider", consumer = "IpvCoreBack")
    public RequestResponsePact validRequestReturnsIssuedCredential(PactDslWithProvider builder) {
        return builder.given("dummyApiKey is a valid api key")
                .given("dummyAccessToken is a valid access token")
                .given("test-subject is a valid subject")
                .given("dummyExperianKbvComponentId is a valid issuer")
                .given("VC givenName is Mary")
                .given("VC familyName is Watson")
                .given("VC birthDate is 1932-02-25")
                .given("VC evidence verificationScore is 2")
                .given("VC evidence txn is dummyTxn")
                .given("VC address uprn is 10022812929")
                .given("VC address organisationName is FINCH GROUP")
                .given("VC address subBuildingName is UNIT 2B")
                .given("VC address buildingNumber is 16")
                .given("VC address buildingName is COY POND BUSINESS PARK")
                .given("VC address dependentStreetName is KINGS PARK")
                .given("VC address streetName is BIG STREET")
                .given("VC address doubleDependentAddressLocality is SOME DISTRICT")
                .given("VC address dependentAddressLocality is LONG EATON")
                .given("VC address addressLocality is GREAT MISSENDEN")
                .given("VC address postalCode is HP16 0AL")
                .given("VC address addressCountry is GB")
                .given(
                        "VC evidence checkDetails are multiple_choice, multiple_choice, multiple_choice")
                .given("VC evidence checkDetails kbvQuality are 2, 2 and 1")
                .uponReceiving("Valid credential request for VC")
                .path("/credential")
                .method("POST")
                .headers("x-api-key", PRIVATE_API_KEY, "Authorization", "Bearer dummyAccessToken")
                .willRespondWith()
                .status(200)
                .body(
                        new PactJwtIgnoreSignatureBodyBuilder(
                                VALID_VC_HEADER, VALID_VC_BODY, VALID_VC_SIGNATURE))
                .toPact();
    }

    @Test
    @PactTestFor(pactMethod = "validRequestReturnsIssuedCredential")
    void fetchVerifiableCredential_whenCalledAgainstExperianKbvCri_retrievesAValidVc(
            MockServer mockServer)
            throws URISyntaxException, CriApiException, JsonProcessingException {
        // Arrange
        var credentialIssuerConfig = getMockCredentialIssuerConfig(mockServer);
        configureMockConfigService(credentialIssuerConfig);

        // We need to generate a fixed request, so we set the secure token and expiry to constant
        // values.
        var underTest =
                new CriApiService(
                        mockConfigService,
                        mockKmsEs256SignerFactory,
                        mockSecureTokenHelper,
                        CURRENT_TIME);

        // Act
        var verifiableCredentialResponse =
                underTest.fetchVerifiableCredential(
                        new BearerAccessToken("dummyAccessToken"),
                        EXPERIAN_KBV.getId(),
                        getCriOAuthSessionItem());

        // Assert
        var verifiableCredentialJwtValidator = getVerifiableCredentialValidator();
        verifiableCredentialResponse
                .getVerifiableCredentials()
                .forEach(
                        credential -> {
                            try {
                                var vc =
                                        verifiableCredentialJwtValidator.parseAndValidate(
                                                TEST_USER,
                                                EXPERIAN_KBV.getId(),
                                                credential,
                                                VerifiableCredentialConstants
                                                        .IDENTITY_CHECK_CREDENTIAL_TYPE,
                                                EC_PRIVATE_KEY_JWK,
                                                TEST_ISSUER,
                                                false);

                                JsonNode credentialSubject =
                                        objectMapper
                                                .readTree(vc.getClaimsSet().toString())
                                                .get("vc")
                                                .get("credentialSubject");

                                JsonNode checkDetails =
                                        objectMapper
                                                .readTree(vc.getClaimsSet().toString())
                                                .get("vc")
                                                .get("evidence")
                                                .get(0)
                                                .get("checkDetails");

                                JsonNode nameParts =
                                        credentialSubject.get("name").get(0).get("nameParts");
                                JsonNode addressNode = credentialSubject.get("address").get(0);
                                assertEquals("GivenName", nameParts.get(0).get("type").asText());
                                assertEquals("FamilyName", nameParts.get(1).get("type").asText());
                                assertEquals("Mary", nameParts.get(0).get("value").asText());
                                assertEquals("Watson", nameParts.get(1).get("value").asText());
                                assertEquals("10022812929", addressNode.get("uprn").asText());
                                assertEquals(
                                        "FINCH GROUP",
                                        addressNode.get("organisationName").asText());
                                assertEquals(
                                        "UNIT 2B", addressNode.get("subBuildingName").asText());
                                assertEquals("16", addressNode.get("buildingNumber").asText());
                                assertEquals(
                                        "COY POND BUSINESS PARK",
                                        addressNode.get("buildingName").asText());
                                assertEquals(
                                        "KINGS PARK",
                                        addressNode.get("dependentStreetName").asText());
                                assertEquals("BIG STREET", addressNode.get("streetName").asText());
                                assertEquals(
                                        "SOME DISTRICT",
                                        addressNode.get("doubleDependentAddressLocality").asText());
                                assertEquals(
                                        "LONG EATON",
                                        addressNode.get("dependentAddressLocality").asText());
                                assertEquals(
                                        "GREAT MISSENDEN",
                                        addressNode.get("addressLocality").asText());
                                assertEquals("HP16 0AL", addressNode.get("postalCode").asText());
                                assertEquals("GB", addressNode.get("addressCountry").asText());

                                assertEquals(3, checkDetails.size());
                            } catch (VerifiableCredentialException | JsonProcessingException e) {
                                throw new RuntimeException(e);
                            }
                        });
    }

    @Pact(provider = "ExperianKbvCriProvider", consumer = "IpvCoreBack")
    public RequestResponsePact validRequestReturnsIssuedCredentialWithFailedAnswer(
            PactDslWithProvider builder) {
        return builder.given("dummyApiKey is a valid api key")
                .given("dummyAccessToken is a valid access token")
                .given("test-subject is a valid subject")
                .given("dummyExperianKbvComponentId is a valid issuer")
                .given("VC givenName is Mary")
                .given("VC familyName is Watson")
                .given("VC birthDate is 1932-02-25")
                .given("VC evidence verificationScore is 0")
                .given("VC evidence txn is dummyTxn")
                .given("VC address uprn is 10022812929")
                .given("VC address organisationName is FINCH GROUP")
                .given("VC address subBuildingName is UNIT 2B")
                .given("VC address buildingNumber is 16")
                .given("VC address buildingName is COY POND BUSINESS PARK")
                .given("VC address dependentStreetName is KINGS PARK")
                .given("VC address streetName is BIG STREET")
                .given("VC address doubleDependentAddressLocality is SOME DISTRICT")
                .given("VC address dependentAddressLocality is LONG EATON")
                .given("VC address addressLocality is GREAT MISSENDEN")
                .given("VC address postalCode is HP16 0AL")
                .given("VC address addressCountry is GB")
                .given("VC evidence checkDetails are multiple_choice, multiple_choice")
                .given("VC evidence checkDetails kbvQuality are 3 and 2")
                .uponReceiving("Valid credential request for VC")
                .path("/credential")
                .method("POST")
                .headers("x-api-key", PRIVATE_API_KEY, "Authorization", "Bearer dummyAccessToken")
                .willRespondWith()
                .status(200)
                .body(
                        new PactJwtIgnoreSignatureBodyBuilder(
                                VALID_VC_HEADER,
                                VALID_THIN_FILE_VC_BODY,
                                VALID_THIN_FILE_VC_SIGNATURE))
                .toPact();
    }

    @Test
    @PactTestFor(pactMethod = "validRequestReturnsIssuedCredentialWithFailedAnswer")
    void
            fetchVerifiableCredential_whenCalledAgainstExperianKbvCri_retrievesAValidVcWithFailedAnswer(
                    MockServer mockServer)
                    throws URISyntaxException, CriApiException, JsonProcessingException {
        // Arrange
        var credentialIssuerConfig = getMockCredentialIssuerConfig(mockServer);
        configureMockConfigService(credentialIssuerConfig);

        // We need to generate a fixed request, so we set the secure token and expiry to constant
        // values.
        var underTest =
                new CriApiService(
                        mockConfigService,
                        mockKmsEs256SignerFactory,
                        mockSecureTokenHelper,
                        CURRENT_TIME);

        // Act
        var verifiableCredentialResponse =
                underTest.fetchVerifiableCredential(
                        new BearerAccessToken("dummyAccessToken"),
                        EXPERIAN_KBV.getId(),
                        getCriOAuthSessionItem());

        // Assert
        var verifiableCredentialJwtValidator = getVerifiableCredentialValidator();
        verifiableCredentialResponse
                .getVerifiableCredentials()
                .forEach(
                        credential -> {
                            try {
                                var vc =
                                        verifiableCredentialJwtValidator.parseAndValidate(
                                                TEST_USER,
                                                EXPERIAN_KBV.getId(),
                                                credential,
                                                VerifiableCredentialConstants
                                                        .IDENTITY_CHECK_CREDENTIAL_TYPE,
                                                EC_PRIVATE_KEY_JWK,
                                                TEST_ISSUER,
                                                false);

                                JsonNode credentialSubject =
                                        objectMapper
                                                .readTree(vc.getClaimsSet().toString())
                                                .get("vc")
                                                .get("credentialSubject");

                                JsonNode nameParts =
                                        credentialSubject.get("name").get(0).get("nameParts");

                                JsonNode addressNode = credentialSubject.get("address").get(0);
                                assertEquals("GivenName", nameParts.get(0).get("type").asText());
                                assertEquals("FamilyName", nameParts.get(1).get("type").asText());
                                assertEquals("Mary", nameParts.get(0).get("value").asText());
                                assertEquals("Watson", nameParts.get(1).get("value").asText());
                                assertEquals("10022812929", addressNode.get("uprn").asText());
                                assertEquals(
                                        "FINCH GROUP",
                                        addressNode.get("organisationName").asText());
                                assertEquals(
                                        "UNIT 2B", addressNode.get("subBuildingName").asText());
                                assertEquals("16", addressNode.get("buildingNumber").asText());
                                assertEquals(
                                        "COY POND BUSINESS PARK",
                                        addressNode.get("buildingName").asText());
                                assertEquals(
                                        "KINGS PARK",
                                        addressNode.get("dependentStreetName").asText());
                                assertEquals("BIG STREET", addressNode.get("streetName").asText());
                                assertEquals(
                                        "SOME DISTRICT",
                                        addressNode.get("doubleDependentAddressLocality").asText());
                                assertEquals(
                                        "LONG EATON",
                                        addressNode.get("dependentAddressLocality").asText());
                                assertEquals(
                                        "GREAT MISSENDEN",
                                        addressNode.get("addressLocality").asText());
                                assertEquals("HP16 0AL", addressNode.get("postalCode").asText());
                                assertEquals("GB", addressNode.get("addressCountry").asText());

                            } catch (VerifiableCredentialException | JsonProcessingException e) {
                                throw new RuntimeException(e);
                            }
                        });
    }

    @Pact(provider = "ExperianKbvCriProvider", consumer = "IpvCoreBack")
    public RequestResponsePact invalidAccessTokenReturns401(PactDslWithProvider builder) {
        return builder.given("dummyApiKey is a valid api key")
                .given("dummyInvalidAccessToken is an invalid access token")
                .given("test-subject is a valid subject")
                .given("dummyExperianKbvComponentId is a valid issuer")
                .uponReceiving("Invalid credential request due to invalid access token")
                .path("/credential")
                .method("POST")
                .headers(
                        "x-api-key",
                        PRIVATE_API_KEY,
                        "Authorization",
                        "Bearer dummyInvalidAccessToken")
                .willRespondWith()
                .status(401)
                .toPact();
    }

    @Test
    @PactTestFor(pactMethod = "invalidAccessTokenReturns401")
    void
            fetchVerifiableCredential_whenCalledAgainstExperianKbvCriWithInvalidAuthCode_throwsAnException(
                    MockServer mockServer) throws URISyntaxException {
        // Arrange
        var credentialIssuerConfig = getMockCredentialIssuerConfig(mockServer);
        configureMockConfigService(credentialIssuerConfig);

        // We need to generate a fixed request, so we set the secure token and expiry to constant
        // values.
        var underTest =
                new CriApiService(
                        mockConfigService,
                        mockKmsEs256SignerFactory,
                        mockSecureTokenHelper,
                        CURRENT_TIME);

        // Act
        CriApiException exception =
                assertThrows(
                        CriApiException.class,
                        () ->
                                underTest.fetchVerifiableCredential(
                                        new BearerAccessToken("dummyInvalidAccessToken"),
                                        EXPERIAN_KBV.getId(),
                                        getCriOAuthSessionItem()));

        // Assert
        assertThat(
                exception.getErrorResponse(),
                is(ErrorResponse.FAILED_TO_GET_CREDENTIAL_FROM_ISSUER));
        assertThat(exception.getHttpStatusCode(), is(HTTPResponse.SC_SERVER_ERROR));
    }

    @Pact(provider = "ExperianKbvCriProvider", consumer = "IpvCoreBack")
    public RequestResponsePact validRequestReturnsIssuedCredentialWithCi(
            PactDslWithProvider builder) {
        return builder.given("dummyApiKey is a valid api key")
                .given("dummyAccessToken is a valid access token")
                .given("test-subject is a valid subject")
                .given("dummyExperianKbvComponentId is a valid issuer")
                .given("VC givenName is Mary")
                .given("VC familyName is Watson")
                .given("VC birthDate is 1932-02-25")
                .given("VC evidence verificationScore is 0")
                .given("VC evidence txn is dummyTxn")
                .given("VC address uprn is 10022812929")
                .given("VC address organisationName is FINCH GROUP")
                .given("VC address subBuildingName is UNIT 2B")
                .given("VC address buildingNumber is 16")
                .given("VC address buildingName is COY POND BUSINESS PARK")
                .given("VC address dependentStreetName is KINGS PARK")
                .given("VC address streetName is BIG STREET")
                .given("VC address doubleDependentAddressLocality is SOME DISTRICT")
                .given("VC address dependentAddressLocality is LONG EATON")
                .given("VC address addressLocality is GREAT MISSENDEN")
                .given("VC address postalCode is HP16 0AL")
                .given("VC address addressCountry is GB")
                .given("VC evidence checkDetails are multiple_choice")
                .given("VC evidence checkDetails kbvQuality are 3")
                .given("VC evidence failedCheckDetails are multiple_choice, multiple_choice")
                .given("VC ci is A03")
                .uponReceiving("Valid credential request for VC with CI")
                .path("/credential")
                .method("POST")
                .headers("x-api-key", PRIVATE_API_KEY, "Authorization", "Bearer dummyAccessToken")
                .willRespondWith()
                .body(
                        new PactJwtIgnoreSignatureBodyBuilder(
                                VALID_VC_HEADER, FAILED_VC_BODY, FAILED_VC_SIGNATURE))
                .status(200)
                .toPact();
    }

    @Test
    @PactTestFor(pactMethod = "validRequestReturnsIssuedCredentialWithCi")
    void fetchVerifiableCredential_whenCalledAgainstExperianKbvCri_retrievesAValidVcWithACi(
            MockServer mockServer)
            throws URISyntaxException, CriApiException, JsonProcessingException {
        // Arrange
        var credentialIssuerConfig = getMockCredentialIssuerConfig(mockServer);
        configureMockConfigService(credentialIssuerConfig);

        // We need to generate a fixed request, so we set the secure token and expiry to constant
        // values.
        var underTest =
                new CriApiService(
                        mockConfigService,
                        mockKmsEs256SignerFactory,
                        mockSecureTokenHelper,
                        CURRENT_TIME);

        // Act
        var verifiableCredentialResponse =
                underTest.fetchVerifiableCredential(
                        new BearerAccessToken("dummyAccessToken"),
                        EXPERIAN_KBV.getId(),
                        getCriOAuthSessionItem());

        // Assert
        var verifiableCredentialJwtValidator = getVerifiableCredentialValidator();
        verifiableCredentialResponse
                .getVerifiableCredentials()
                .forEach(
                        credential -> {
                            try {
                                var vc =
                                        verifiableCredentialJwtValidator.parseAndValidate(
                                                TEST_USER,
                                                EXPERIAN_KBV.getId(),
                                                credential,
                                                VerifiableCredentialConstants
                                                        .IDENTITY_CHECK_CREDENTIAL_TYPE,
                                                EC_PRIVATE_KEY_JWK,
                                                TEST_ISSUER,
                                                false);

                                JsonNode credentialSubject =
                                        objectMapper
                                                .readTree(vc.getClaimsSet().toString())
                                                .get("vc")
                                                .get("credentialSubject");

                                JsonNode nameParts =
                                        credentialSubject.get("name").get(0).get("nameParts");

                                JsonNode vcClaim =
                                        objectMapper
                                                .readTree(vc.getClaimsSet().toString())
                                                .get("vc");

                                JsonNode evidence = vcClaim.get("evidence").get(0);
                                JsonNode ciNode = evidence.get("ci");
                                JsonNode addressNode = credentialSubject.get("address").get(0);

                                JsonNode failedCheckDetailsNode =
                                        evidence.get("failedCheckDetails");

                                assertEquals("GivenName", nameParts.get(0).get("type").asText());
                                assertEquals("FamilyName", nameParts.get(1).get("type").asText());
                                assertEquals("Mary", nameParts.get(0).get("value").asText());
                                assertEquals("Watson", nameParts.get(1).get("value").asText());
                                assertEquals("10022812929", addressNode.get("uprn").asText());
                                assertEquals(
                                        "FINCH GROUP",
                                        addressNode.get("organisationName").asText());
                                assertEquals(
                                        "UNIT 2B", addressNode.get("subBuildingName").asText());
                                assertEquals("16", addressNode.get("buildingNumber").asText());
                                assertEquals(
                                        "COY POND BUSINESS PARK",
                                        addressNode.get("buildingName").asText());
                                assertEquals(
                                        "KINGS PARK",
                                        addressNode.get("dependentStreetName").asText());
                                assertEquals("BIG STREET", addressNode.get("streetName").asText());
                                assertEquals(
                                        "SOME DISTRICT",
                                        addressNode.get("doubleDependentAddressLocality").asText());
                                assertEquals(
                                        "LONG EATON",
                                        addressNode.get("dependentAddressLocality").asText());
                                assertEquals(
                                        "GREAT MISSENDEN",
                                        addressNode.get("addressLocality").asText());
                                assertEquals("HP16 0AL", addressNode.get("postalCode").asText());
                                assertEquals("GB", addressNode.get("addressCountry").asText());

                                assertEquals("A03", ciNode.get(0).asText());

                                assertEquals(
                                        "multiple_choice",
                                        failedCheckDetailsNode
                                                .get(0)
                                                .get("kbvResponseMode")
                                                .asText());
                                assertEquals(
                                        "multiple_choice",
                                        failedCheckDetailsNode
                                                .get(1)
                                                .get("kbvResponseMode")
                                                .asText());
                                assertEquals(
                                        "kbv",
                                        failedCheckDetailsNode.get(0).get("checkMethod").asText());
                            } catch (VerifiableCredentialException | JsonProcessingException e) {
                                throw new RuntimeException(e);
                            }
                        });
    }

    private void configureMockConfigService(OauthCriConfig credentialIssuerConfig) {
        ContraIndicatorConfig ciConfig = new ContraIndicatorConfig(null, 4, null, null);
        Map<String, ContraIndicatorConfig> ciConfigMap = new HashMap<>();
        ciConfigMap.put("A03", ciConfig);

        when(mockConfigService.getOauthCriConfig(any())).thenReturn(credentialIssuerConfig);
        when(mockConfigService.getCriPrivateApiKey(any())).thenReturn(PRIVATE_API_KEY);
        // This mock doesn't get reached in error cases, but it would be messy to explicitly not set
        // it
        Mockito.lenient()
                .when(mockConfigService.getContraIndicatorConfigMap())
                .thenReturn(ciConfigMap);
    }

    @NotNull
    private VerifiableCredentialValidator getVerifiableCredentialValidator() {
        return new VerifiableCredentialValidator(
                mockConfigService,
                ((exactMatchClaims, requiredClaims) ->
                        new FixedTimeJWTClaimsVerifier<>(
                                exactMatchClaims,
                                requiredClaims,
                                Date.from(CURRENT_TIME.instant()))));
    }

    @NotNull
    private static CriOAuthSessionItem getCriOAuthSessionItem() {
        return new CriOAuthSessionItem(
                "dummySessionId", "dummyOAuthSessionId", "dummyCriId", "dummyConnection", 900);
    }

    @NotNull
    private static CriCallbackRequest getCallbackRequest(String authCode) {
        return new CriCallbackRequest(
                authCode,
                EXPERIAN_KBV.getId(),
                "dummySessionId",
                "https://identity.staging.account.gov.uk/credential-issuer/callback?id=kbv",
                "dummyState",
                null,
                null,
                "dummyIpAddress",
                "dummyDeviceInformation",
                List.of("dummyFeatureSet"));
    }

    @NotNull
    private static OauthCriConfig getMockCredentialIssuerConfig(MockServer mockServer)
            throws URISyntaxException {
        return OauthCriConfig.builder()
                .tokenUrl(new URI("http://localhost:" + mockServer.getPort() + "/token"))
                .credentialUrl(new URI("http://localhost:" + mockServer.getPort() + "/credential"))
                .authorizeUrl(new URI("http://localhost:" + mockServer.getPort() + "/authorize"))
                .clientId(IPV_CORE_CLIENT_ID)
                .signingKey(EC_PRIVATE_KEY_JWK)
                .encryptionKey(RSA_ENCRYPTION_PUBLIC_JWK)
                .componentId(TEST_ISSUER)
                .clientCallbackUrl(
                        URI.create(
                                "https://identity.staging.account.gov.uk/credential-issuer/callback?id=kbv"))
                .requiresApiKey(true)
                .requiresAdditionalEvidence(false)
                .build();
    }
}
