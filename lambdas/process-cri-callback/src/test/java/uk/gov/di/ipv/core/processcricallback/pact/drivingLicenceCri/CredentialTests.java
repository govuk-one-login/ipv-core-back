package uk.gov.di.ipv.core.processcricallback.pact.drivingLicenceCri;

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
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.domain.ContraIndicatorConfig;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.dto.CriCallbackRequest;
import uk.gov.di.ipv.core.library.dto.OauthCriConfig;
import uk.gov.di.ipv.core.library.exceptions.VerifiableCredentialException;
import uk.gov.di.ipv.core.library.helpers.FixedTimeJWTClaimsVerifier;
import uk.gov.di.ipv.core.library.helpers.SecureTokenHelper;
import uk.gov.di.ipv.core.library.kmses256signer.KmsEs256SignerFactory;
import uk.gov.di.ipv.core.library.pacttesthelpers.PactJwtIgnoreSignatureBodyBuilder;
import uk.gov.di.ipv.core.library.persistence.item.CriOAuthSessionItem;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.verifiablecredential.validator.VerifiableCredentialJwtValidator;
import uk.gov.di.ipv.core.processcricallback.exception.CriApiException;
import uk.gov.di.ipv.core.processcricallback.service.CriApiService;

import java.net.URI;
import java.net.URISyntaxException;
import java.sql.Date;
import java.text.ParseException;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

@Disabled("PACT tests should not be run in build pipelines at this time")
@ExtendWith(PactConsumerTestExt.class)
@ExtendWith(MockitoExtension.class)
@PactTestFor(providerName = "DrivingLicenceVcProvider")
@MockServerConfig(hostInterface = "localhost", port = "1234")
class CredentialTests {
    private static final String TEST_USER = "test-subject";
    private static final String TEST_ISSUER = "dummyDrivingLicenceComponentId";
    private static final String IPV_CORE_CLIENT_ID = "ipv-core";
    private static final String PRIVATE_API_KEY = "dummyApiKey";
    private static final Clock CURRENT_TIME =
            Clock.fixed(Instant.parse("2099-01-01T00:00:00.00Z"), ZoneOffset.UTC);
    private static final String CRI_SIGNING_PRIVATE_KEY_JWK =
            """
            {"kty":"EC","d":"OXt0P05ZsQcK7eYusgIPsqZdaBCIJiW4imwUtnaAthU","crv":"P-256","x":"E9ZzuOoqcVU4pVB9rpmTzezjyOPRlOmPGJHKi8RSlIM","y":"KlTMZthHZUkYz5AleTQ8jff0TJiS3q2OB9L5Fw4xA04"}
            """;
    private static final String CRI_RSA_ENCRYPTION_PUBLIC_JWK =
            """
            {"kty":"RSA","e":"AQAB","n":"vyapkvJXLwpYRJjbkQD99V2gcPEUKrO3dwjcAA9TPkLucQEZvYZvb7-wfSHxlvJlJcdS20r5PKKmqdPeW3Y4ir3WsVVeiht2iOZUreUO5O3V3o7ImvEjPS_2_ZKMHCwUf51a6WGOaDjO87OX_bluV2dp01n-E3kiIl6RmWCVywjn13fX3jsX0LMCM_bt3HofJqiYhhNymEwh39oR_D7EE5sLUii2XvpTYPa6L_uPwdKa4vRl4h4owrWEJaJifMorGcvqhCK1JOHqgknN_3cb_ns9Px6ynQCeFXvBDJy4q71clkBq_EZs5227Y1S222wXIwUYN8w5YORQe3M-pCIh1Q"}
            """;

    private static final ObjectMapper objectMapper = new ObjectMapper();

    // We hardcode the VC headers and bodies like this so that it is easy to update them from JSON
    // sent by the CRI team
    private static final String VALID_VC_HEADER =
            """
            {
              "alg": "ES256",
              "typ": "JWT"
            }
            """;
    // 2099-01-01 00:00:00 is 4070908800 in epoch seconds
    private static final String VALID_DVLA_VC_BODY =
            """
            {
              "sub": "test-subject",
              "iss": "dummyDrivingLicenceComponentId",
              "nbf": 4070908800,
              "exp": 4070909400,
              "vc": {
                "evidence": [
                  {
                    "activityHistoryScore": 1,
                    "checkDetails": [
                      {
                        "identityCheckPolicy": "published",
                        "activityFrom": "1982-05-23",
                        "checkMethod": "data"
                      }
                    ],
                    "validityScore": 2,
                    "strengthScore": 3,
                    "txn": "dummyTxn",
                    "type": "IDENTITY_CHECK"
                  }
                ],
                "credentialSubject": {
                  "address": [
                    {
                      "addressCountry": "GB",
                      "postalCode": "BS981TL"
                    }
                  ],
                  "name": [
                    {
                      "nameParts": [
                        {
                          "type": "GivenName",
                          "value": "PETER"
                        },
                        {
                          "type": "GivenName",
                          "value": "BENJAMIN"
                        },
                        {
                          "type": "FamilyName",
                          "value": "PARKER"
                        }
                      ]
                    }
                  ],
                  "drivingPermit": [
                    {
                      "expiryDate": "2062-12-09",
                      "issueNumber": "12",
                      "issuedBy": "DVLA",
                      "personalNumber": "PARKE610112PBFGH",
                      "issueDate": "1982-05-23"
                    }
                  ],
                  "birthDate": [
                    {
                      "value": "1962-10-11"
                    }
                  ]
                },
                "type": [
                  "VerifiableCredential",
                  "IdentityCheckCredential"
                ]
              }
            }
            """;
    // If we generate the signature in code it will be different each time, so we need to generate a
    // valid signature (using https://jwt.io works well) and record it here so the PACT file doesn't
    // change each time we run the tests.
    private static final String VALID_DVLA_VC_SIGNATURE =
            "kZLEZfJU5XI7lEs0J-BZi5he4DBF5SUWauozDHsvvQRfCobVGasX4BWodMA3rBY2V9BeQE9KdQQ7L3Hg_zJhGw";

    private static final String FAILED_DVLA_VC_BODY =
            """
            {
              "sub": "test-subject",
              "iss": "dummyDrivingLicenceComponentId",
              "nbf": 4070908800,
              "exp": 4070909400,
              "vc": {
                "evidence": [
                  {
                    "activityHistoryScore": 0,
                    "ci": ["D02"],
                    "failedCheckDetails": [
                      {
                        "identityCheckPolicy": "published",
                        "checkMethod": "data"
                      }
                    ],
                    "validityScore": 0,
                    "strengthScore": 3,
                    "txn": "dummyTxn",
                    "type": "IDENTITY_CHECK"
                  }
                ],
                "credentialSubject": {
                  "address": [
                    {
                      "addressCountry": "GB",
                      "postalCode": "BS981TL"
                    }
                  ],
                  "name": [
                    {
                      "nameParts": [
                        {
                          "type": "GivenName",
                          "value": "PETER"
                        },
                        {
                          "type": "GivenName",
                          "value": "BENJAMIN"
                        },
                        {
                          "type": "FamilyName",
                          "value": "PARKER"
                        }
                      ]
                    }
                  ],
                  "drivingPermit": [
                    {
                      "expiryDate": "2062-12-09",
                      "issueNumber": "12",
                      "issuedBy": "DVLA",
                      "personalNumber": "PARKE610112PBFGH",
                      "issueDate": "1982-05-23"
                    }
                  ],
                  "birthDate": [
                    {
                      "value": "1962-10-11"
                    }
                  ]
                },
                "type": [
                  "VerifiableCredential",
                  "IdentityCheckCredential"
                ]
              }
            }
            """;
    // If we generate the signature in code it will be different each time, so we need to generate a
    // valid signature (using https://jwt.io works well) and record it here so the PACT file doesn't
    // change each time we run the tests.
    private static final String FAILED_DVLA_VC_SIGNATURE =
            "BtCD3UyqQHhNQLd7RotfC3lGYk0ooGzTCBAAMuT6GHJL_P5Punkml7xWfAxWhmJ9w1p-oZl8Kw-aCv5WUNrTHA";

    // 2099-01-01 00:00:00 is 4070908800 in epoch seconds
    private static final String VALID_DVA_VC_BODY =
            """
            {
              "sub": "test-subject",
              "iss": "dummyDrivingLicenceComponentId",
              "nbf": 4070908800,
              "exp": 4070909400,
              "vc": {
                "evidence": [
                  {
                    "activityHistoryScore": 1,
                    "checkDetails": [
                      {
                        "identityCheckPolicy": "published",
                        "activityFrom": "1982-05-23",
                        "checkMethod": "data"
                      }
                    ],
                    "validityScore": 2,
                    "strengthScore": 3,
                    "txn": "dummyTxn",
                    "type": "IDENTITY_CHECK"
                  }
                ],
                "credentialSubject": {
                  "address": [
                    {
                      "addressCountry": "GB",
                      "postalCode": "BS981TL"
                    }
                  ],
                  "name": [
                    {
                      "nameParts": [
                        {
                          "type": "GivenName",
                          "value": "PETER"
                        },
                        {
                          "type": "GivenName",
                          "value": "BENJAMIN"
                        },
                        {
                          "type": "FamilyName",
                          "value": "PARKER"
                        }
                      ]
                    }
                  ],
                  "drivingPermit": [
                    {
                      "expiryDate": "2062-12-09",
                      "issuedBy": "DVA",
                      "personalNumber": "55667788",
                      "issueDate": "1982-05-23"
                    }
                  ],
                  "birthDate": [
                    {
                      "value": "1962-10-11"
                    }
                  ]
                },
                "type": [
                  "VerifiableCredential",
                  "IdentityCheckCredential"
                ]
              }
            }
            """;
    // If we generate the signature in code it will be different each time, so we need to generate a
    // valid signature (using https://jwt.io works well) and record it here so the PACT file doesn't
    // change each time we run the tests.
    private static final String VALID_DVA_VC_SIGNATURE =
            "OAb52qC_2MO94SbdJVxFvy9vTwrFD3qBAndTe1qDxjATZdTDP6dYZXBDjX4OozRuD2b7sZP8gVzYUPdJ09CWfQ";

    private static final String FAILED_DVA_VC_BODY =
            """
            {
              "sub": "test-subject",
              "iss": "dummyDrivingLicenceComponentId",
              "nbf": 4070908800,
              "exp": 4070909400,
              "vc": {
                "evidence": [
                  {
                    "activityHistoryScore": 0,
                    "ci": ["D02"],
                    "failedCheckDetails": [
                      {
                        "identityCheckPolicy": "published",
                        "checkMethod": "data"
                      }
                    ],
                    "validityScore": 0,
                    "strengthScore": 3,
                    "txn": "dummyTxn",
                    "type": "IDENTITY_CHECK"
                  }
                ],
                "credentialSubject": {
                  "address": [
                    {
                      "addressCountry": "GB",
                      "postalCode": "BS981TL"
                    }
                  ],
                  "name": [
                    {
                      "nameParts": [
                        {
                          "type": "GivenName",
                          "value": "PETER"
                        },
                        {
                          "type": "GivenName",
                          "value": "BENJAMIN"
                        },
                        {
                          "type": "FamilyName",
                          "value": "PARKER"
                        }
                      ]
                    }
                  ],
                  "drivingPermit": [
                    {
                      "expiryDate": "2062-12-09",
                      "issuedBy": "DVA",
                      "personalNumber": "55667780",
                      "issueDate": "1982-05-23"
                    }
                  ],
                  "birthDate": [
                    {
                      "value": "1962-10-11"
                    }
                  ]
                },
                "type": [
                  "VerifiableCredential",
                  "IdentityCheckCredential"
                ]
              }
            }
            """;
    // If we generate the signature in code it will be different each time, so we need to generate a
    // valid signature (using https://jwt.io works well) and record it here so the PACT file doesn't
    // change each time we run the tests.
    private static final String FAILED_DVA_VC_SIGNATURE =
            "Olph1tC4Tlbz2aQ2d5kaYjuXtZFowhelxS2rP_KmSNI50ZZMRa1z-ClE-vZDqKD4ETDs4871w_pGb2vh6nepVQ";

    @Mock private ConfigService mockConfigService;
    @Mock private KmsEs256SignerFactory mockKmsEs256SignerFactory;
    @Mock private JWSSigner mockSigner;
    @Mock private SecureTokenHelper mockSecureTokenHelper;

    @Pact(provider = "DrivingLicenceCriProvider", consumer = "IpvCoreBack")
    public RequestResponsePact validRequestReturnsDvlaIssuedCredential(
            PactDslWithProvider builder) {
        return builder.given("dummyApiKey is a valid api key")
                .given("dummyAccessToken is a valid access token")
                .given("test-subject is a valid subject")
                .given("dummyDrivingLicenceComponentId is a valid issuer")
                .given("VC evidence activityHistoryScore is 1")
                .given("VC evidence validityScore is 2")
                .given("VC evidence txn is dummyTxn")
                .given("VC evidence checkDetails activityFrom is 1982-05-23")
                .given("VC address is BS981TL, GB")
                .given("VC is for Peter Benjamin Parker")
                .given("VC driving licence expiryDate is 2062-12-09")
                .given("VC driving licence issueNumber is 12")
                .given("VC driving licence issuedBy is DVLA")
                .given("VC driving licence personalNumber is PARKE610112PBFGH")
                .given("VC driving licence issuedDate is 1982-05-23")
                .given("VC birthDate is 1962-10-11")
                .uponReceiving("Valid credential request for DVLA VC")
                .path("/credential/issue")
                .method("POST")
                .headers("x-api-key", PRIVATE_API_KEY, "Authorization", "Bearer dummyAccessToken")
                .willRespondWith()
                .status(200)
                .body(
                        new PactJwtIgnoreSignatureBodyBuilder(
                                VALID_VC_HEADER, VALID_DVLA_VC_BODY, VALID_DVLA_VC_SIGNATURE))
                .toPact();
    }

    @Test
    @PactTestFor(pactMethod = "validRequestReturnsDvlaIssuedCredential")
    void fetchVerifiableCredential_whenCalledAgainstDrivingLicenceCri_retrievesAValidDvlaVc(
            MockServer mockServer) throws URISyntaxException, CriApiException {
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
                        getCallbackRequest("dummyAuthCode", credentialIssuerConfig),
                        getCriOAuthSessionItem());

        // Assert
        var verifiableCredentialJwtValidator = getVerifiableCredentialJwtValidator();
        verifiableCredentialResponse
                .getVerifiableCredentials()
                .forEach(
                        credential -> {
                            try {
                                verifiableCredentialJwtValidator.validate(
                                        credential, credentialIssuerConfig, TEST_USER);

                                JsonNode credentialSubject =
                                        objectMapper
                                                .readTree(credential.getJWTClaimsSet().toString())
                                                .get("vc")
                                                .get("credentialSubject");

                                JsonNode addressNode = credentialSubject.get("address").get(0);
                                JsonNode nameParts =
                                        credentialSubject.get("name").get(0).get("nameParts");
                                JsonNode birthDateNode = credentialSubject.get("birthDate").get(0);
                                JsonNode drivingPermitNode =
                                        credentialSubject.get("drivingPermit").get(0);

                                assertEquals("GB", addressNode.get("addressCountry").asText());
                                assertEquals("BS981TL", addressNode.get("postalCode").asText());

                                assertEquals("GivenName", nameParts.get(0).get("type").asText());
                                assertEquals("GivenName", nameParts.get(1).get("type").asText());
                                assertEquals("FamilyName", nameParts.get(2).get("type").asText());
                                assertEquals("PETER", nameParts.get(0).get("value").asText());
                                assertEquals("BENJAMIN", nameParts.get(1).get("value").asText());
                                assertEquals("PARKER", nameParts.get(2).get("value").asText());

                                assertEquals(
                                        "2062-12-09", drivingPermitNode.get("expiryDate").asText());
                                assertEquals(
                                        "PARKE610112PBFGH",
                                        drivingPermitNode.get("personalNumber").asText());
                                assertEquals("DVLA", drivingPermitNode.get("issuedBy").asText());

                                assertEquals("1962-10-11", birthDateNode.get("value").asText());
                            } catch (VerifiableCredentialException
                                    | ParseException
                                    | JsonProcessingException e) {
                                throw new RuntimeException(e);
                            }
                        });
    }

    @Pact(provider = "DrivingLicenceCriProvider", consumer = "IpvCoreBack")
    public RequestResponsePact validRequestReturnsDvlaResponseWithCi(PactDslWithProvider builder) {
        return builder.given("dummyApiKey is a valid api key")
                .given("dummyAccessToken is a valid access token")
                .given("test-subject is a valid subject")
                .given("dummyDrivingLicenceComponentId is a valid issuer")
                .given("VC has a CI of D02")
                .given("VC evidence txn is dummyTxn")
                .given("VC evidence checkDetails activityFrom is 1982-05-23")
                .given("VC address is BS981TL, GB")
                .given("VC is for Peter Benjamin Parker")
                .given("VC driving licence expiryDate is 2062-12-09")
                .given("VC driving licence issueNumber is 12")
                .given("VC driving licence issuedBy is DVLA")
                .given("VC driving licence personalNumber is PARKE610112PBFGH")
                .given("VC driving licence issuedDate is 1982-05-23")
                .given("VC birthDate is 1962-10-11")
                .uponReceiving("Valid credential request for DVLA VC with CI")
                .path("/credential/issue")
                .method("POST")
                .headers("x-api-key", PRIVATE_API_KEY, "Authorization", "Bearer dummyAccessToken")
                .willRespondWith()
                .status(200)
                .body(
                        new PactJwtIgnoreSignatureBodyBuilder(
                                VALID_VC_HEADER, FAILED_DVLA_VC_BODY, FAILED_DVLA_VC_SIGNATURE))
                .toPact();
    }

    @Test
    @PactTestFor(pactMethod = "validRequestReturnsDvlaResponseWithCi")
    void fetchVerifiableCredential_whenCalledAgainstDrivingLicenceCri_retrievesADvlaVcWithACi(
            MockServer mockServer) throws URISyntaxException, CriApiException {
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
                        getCallbackRequest("dummyAuthCode", credentialIssuerConfig),
                        getCriOAuthSessionItem());

        // Assert
        var verifiableCredentialJwtValidator = getVerifiableCredentialJwtValidator();
        verifiableCredentialResponse
                .getVerifiableCredentials()
                .forEach(
                        credential -> {
                            try {
                                verifiableCredentialJwtValidator.validate(
                                        credential, credentialIssuerConfig, TEST_USER);

                                JsonNode vc =
                                        objectMapper
                                                .readTree(credential.getJWTClaimsSet().toString())
                                                .get("vc");

                                JsonNode credentialSubject = vc.get("credentialSubject");
                                JsonNode evidence = vc.get("evidence").get(0);

                                JsonNode ciNode = evidence.get("ci");
                                JsonNode addressNode = credentialSubject.get("address").get(0);
                                JsonNode nameParts =
                                        credentialSubject.get("name").get(0).get("nameParts");
                                JsonNode birthDateNode = credentialSubject.get("birthDate").get(0);
                                JsonNode drivingPermitNode =
                                        credentialSubject.get("drivingPermit").get(0);

                                assertEquals("D02", ciNode.get(0).asText());

                                assertEquals("GB", addressNode.get("addressCountry").asText());
                                assertEquals("BS981TL", addressNode.get("postalCode").asText());

                                assertEquals("GivenName", nameParts.get(0).get("type").asText());
                                assertEquals("GivenName", nameParts.get(1).get("type").asText());
                                assertEquals("FamilyName", nameParts.get(2).get("type").asText());
                                assertEquals("PETER", nameParts.get(0).get("value").asText());
                                assertEquals("BENJAMIN", nameParts.get(1).get("value").asText());
                                assertEquals("PARKER", nameParts.get(2).get("value").asText());

                                assertEquals(
                                        "2062-12-09", drivingPermitNode.get("expiryDate").asText());
                                assertEquals(
                                        "PARKE610112PBFGH",
                                        drivingPermitNode.get("personalNumber").asText());
                                assertEquals("DVLA", drivingPermitNode.get("issuedBy").asText());

                                assertEquals("1962-10-11", birthDateNode.get("value").asText());
                            } catch (VerifiableCredentialException
                                    | ParseException
                                    | JsonProcessingException e) {
                                throw new RuntimeException(e);
                            }
                        });
    }

    @Pact(provider = "DrivingLicenceCriProvider", consumer = "IpvCoreBack")
    public RequestResponsePact validRequestReturnsDvaIssuedCredential(PactDslWithProvider builder) {
        return builder.given("dummyApiKey is a valid api key")
                .given("dummyAccessToken is a valid access token")
                .given("test-subject is a valid subject")
                .given("dummyDrivingLicenceComponentId is a valid issuer")
                .given("VC evidence activityHistoryScore is 1")
                .given("VC evidence validityScore is 2")
                .given("VC evidence txn is dummyTxn")
                .given("VC evidence checkDetails activityFrom is 1982-05-23")
                .given("VC address is BS981TL, GB")
                .given("VC is for Peter Benjamin Parker")
                .given("VC driving licence expiryDate is 2062-12-09")
                .given("VC driving licence issuedBy is DVA")
                .given("VC driving licence personalNumber is 55667788")
                .given("VC driving licence issuedDate is 1982-05-23")
                .given("VC birthDate is 1962-10-11")
                .uponReceiving("Valid credential request for DVA VC")
                .path("/credential/issue")
                .method("POST")
                .headers("x-api-key", PRIVATE_API_KEY, "Authorization", "Bearer dummyAccessToken")
                .willRespondWith()
                .status(200)
                .body(
                        new PactJwtIgnoreSignatureBodyBuilder(
                                VALID_VC_HEADER, VALID_DVA_VC_BODY, VALID_DVA_VC_SIGNATURE))
                .toPact();
    }

    @Test
    @PactTestFor(pactMethod = "validRequestReturnsDvaIssuedCredential")
    void fetchVerifiableCredential_whenCalledAgainstDrivingLicenceCri_retrievesAValidDvaVc(
            MockServer mockServer) throws URISyntaxException, CriApiException {
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
                        getCallbackRequest("dummyAuthCode", credentialIssuerConfig),
                        getCriOAuthSessionItem());

        // Assert
        var verifiableCredentialJwtValidator = getVerifiableCredentialJwtValidator();
        verifiableCredentialResponse
                .getVerifiableCredentials()
                .forEach(
                        credential -> {
                            try {
                                verifiableCredentialJwtValidator.validate(
                                        credential, credentialIssuerConfig, TEST_USER);

                                JsonNode credentialSubject =
                                        objectMapper
                                                .readTree(credential.getJWTClaimsSet().toString())
                                                .get("vc")
                                                .get("credentialSubject");

                                JsonNode addressNode = credentialSubject.get("address").get(0);
                                JsonNode nameParts =
                                        credentialSubject.get("name").get(0).get("nameParts");
                                JsonNode birthDateNode = credentialSubject.get("birthDate").get(0);
                                JsonNode drivingPermitNode =
                                        credentialSubject.get("drivingPermit").get(0);

                                assertEquals("GB", addressNode.get("addressCountry").asText());
                                assertEquals("BS981TL", addressNode.get("postalCode").asText());

                                assertEquals("GivenName", nameParts.get(0).get("type").asText());
                                assertEquals("GivenName", nameParts.get(1).get("type").asText());
                                assertEquals("FamilyName", nameParts.get(2).get("type").asText());
                                assertEquals("PETER", nameParts.get(0).get("value").asText());
                                assertEquals("BENJAMIN", nameParts.get(1).get("value").asText());
                                assertEquals("PARKER", nameParts.get(2).get("value").asText());

                                assertEquals(
                                        "2062-12-09", drivingPermitNode.get("expiryDate").asText());
                                assertEquals(
                                        "55667788",
                                        drivingPermitNode.get("personalNumber").asText());
                                assertEquals("DVA", drivingPermitNode.get("issuedBy").asText());

                                assertEquals("1962-10-11", birthDateNode.get("value").asText());
                            } catch (VerifiableCredentialException
                                    | ParseException
                                    | JsonProcessingException e) {
                                throw new RuntimeException(e);
                            }
                        });
    }

    @Pact(provider = "DrivingLicenceCriProvider", consumer = "IpvCoreBack")
    public RequestResponsePact validRequestReturnsDvaResponseWithCi(PactDslWithProvider builder) {
        return builder.given("dummyApiKey is a valid api key")
                .given("dummyAccessToken is a valid access token")
                .given("test-subject is a valid subject")
                .given("dummyDrivingLicenceComponentId is a valid issuer")
                .given("VC has a CI of D02")
                .given("VC evidence txn is dummyTxn")
                .given("VC evidence checkDetails activityFrom is 1982-05-23")
                .given("VC address is BS981TL, GB")
                .given("VC is for Peter Benjamin Parker")
                .given("VC driving licence expiryDate is 2062-12-09")
                .given("VC driving licence issueNumber is 12")
                .given("VC driving licence issuedBy is DVA")
                .given("VC driving licence personalNumber is 55667780")
                .given("VC driving licence issuedDate is 1982-05-23")
                .given("VC birthDate is 1962-10-11")
                .uponReceiving("Valid credential request for DVA VC with CI")
                .path("/credential/issue")
                .method("POST")
                .headers("x-api-key", PRIVATE_API_KEY, "Authorization", "Bearer dummyAccessToken")
                .willRespondWith()
                .status(200)
                .body(
                        new PactJwtIgnoreSignatureBodyBuilder(
                                VALID_VC_HEADER, FAILED_DVA_VC_BODY, FAILED_DVA_VC_SIGNATURE))
                .toPact();
    }

    @Test
    @PactTestFor(pactMethod = "validRequestReturnsDvaResponseWithCi")
    void fetchVerifiableCredential_whenCalledAgainstDrivingLicenceCri_retrievesADvaVcWithACi(
            MockServer mockServer) throws URISyntaxException, CriApiException {
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
                        getCallbackRequest("dummyAuthCode", credentialIssuerConfig),
                        getCriOAuthSessionItem());

        // Assert
        var verifiableCredentialJwtValidator = getVerifiableCredentialJwtValidator();
        verifiableCredentialResponse
                .getVerifiableCredentials()
                .forEach(
                        credential -> {
                            try {
                                verifiableCredentialJwtValidator.validate(
                                        credential, credentialIssuerConfig, TEST_USER);

                                JsonNode vc =
                                        objectMapper
                                                .readTree(credential.getJWTClaimsSet().toString())
                                                .get("vc");

                                JsonNode credentialSubject = vc.get("credentialSubject");
                                JsonNode evidence = vc.get("evidence").get(0);

                                JsonNode ciNode = evidence.get("ci");
                                JsonNode addressNode = credentialSubject.get("address").get(0);
                                JsonNode nameParts =
                                        credentialSubject.get("name").get(0).get("nameParts");
                                JsonNode birthDateNode = credentialSubject.get("birthDate").get(0);
                                JsonNode drivingPermitNode =
                                        credentialSubject.get("drivingPermit").get(0);

                                assertEquals("D02", ciNode.get(0).asText());

                                assertEquals("GB", addressNode.get("addressCountry").asText());
                                assertEquals("BS981TL", addressNode.get("postalCode").asText());

                                assertEquals("GivenName", nameParts.get(0).get("type").asText());
                                assertEquals("GivenName", nameParts.get(1).get("type").asText());
                                assertEquals("FamilyName", nameParts.get(2).get("type").asText());
                                assertEquals("PETER", nameParts.get(0).get("value").asText());
                                assertEquals("BENJAMIN", nameParts.get(1).get("value").asText());
                                assertEquals("PARKER", nameParts.get(2).get("value").asText());

                                assertEquals(
                                        "2062-12-09", drivingPermitNode.get("expiryDate").asText());
                                assertEquals(
                                        "55667780",
                                        drivingPermitNode.get("personalNumber").asText());
                                assertEquals("DVA", drivingPermitNode.get("issuedBy").asText());

                                assertEquals("1962-10-11", birthDateNode.get("value").asText());
                            } catch (VerifiableCredentialException
                                    | ParseException
                                    | JsonProcessingException e) {
                                throw new RuntimeException(e);
                            }
                        });
    }

    @Pact(provider = "DrivingLicenceCriProvider", consumer = "IpvCoreBack")
    public RequestResponsePact invalidAccessTokenReturns403(PactDslWithProvider builder) {
        return builder.given("dummyApiKey is a valid api key")
                .given("dummyInvalidAccessToken is an invalid access token")
                .given("test-subject is a valid subject")
                .given("dummyDrivingLicenceComponentId is a valid issuer")
                .uponReceiving("Invalid credential request due to invalid access token")
                .path("/credential/issue")
                .method("POST")
                .headers(
                        "x-api-key",
                        PRIVATE_API_KEY,
                        "Authorization",
                        "Bearer dummyInvalidAccessToken")
                .willRespondWith()
                .status(403)
                .toPact();
    }

    @Test
    @PactTestFor(pactMethod = "invalidAccessTokenReturns403")
    void
            fetchVerifiableCredential_whenCalledAgainstDrivingLicenceCriWithInvalidAuthCode_throwsAnException(
                    MockServer mockServer) throws URISyntaxException, CriApiException {
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
                                        getCallbackRequest("dummyAuthCode", credentialIssuerConfig),
                                        getCriOAuthSessionItem()));

        // Assert
        assertThat(
                exception.getErrorResponse(),
                is(ErrorResponse.FAILED_TO_GET_CREDENTIAL_FROM_ISSUER));
        assertThat(exception.getHttpStatusCode(), is(HTTPResponse.SC_SERVER_ERROR));
    }

    @NotNull
    private static CriOAuthSessionItem getCriOAuthSessionItem() {
        return new CriOAuthSessionItem(
                "dummySessionId", "dummyOAuthSessionId", "dummyCriId", "dummyConnection", 900);
    }

    @NotNull
    private static CriCallbackRequest getCallbackRequest(
            String authCode, OauthCriConfig credentialIssuerConfig) {
        return new CriCallbackRequest(
                authCode,
                credentialIssuerConfig.getClientId(),
                "dummySessionId",
                "https://identity.staging.account.gov.uk/credential-issuer/callback?id=drivingLicence",
                "dummyState",
                null,
                null,
                "dummyIpAddress",
                List.of("dummyFeatureSet"));
    }

    @NotNull
    private VerifiableCredentialJwtValidator getVerifiableCredentialJwtValidator() {
        return new VerifiableCredentialJwtValidator(
                mockConfigService,
                ((exactMatchClaims, requiredClaims) ->
                        new FixedTimeJWTClaimsVerifier<>(
                                exactMatchClaims,
                                requiredClaims,
                                Date.from(CURRENT_TIME.instant()))));
    }

    private void configureMockConfigService(OauthCriConfig credentialIssuerConfig) {
        ContraIndicatorConfig ciConfig1 = new ContraIndicatorConfig(null, 4, null, null);
        Map<String, ContraIndicatorConfig> ciConfigMap = new HashMap<>();
        ciConfigMap.put("D02", ciConfig1);

        when(mockConfigService.getOauthCriConfig(any())).thenReturn(credentialIssuerConfig);
        when(mockConfigService.getCriPrivateApiKey(any())).thenReturn(PRIVATE_API_KEY);
        // This mock doesn't get reached in error cases, but it would be messy to explicitly not set
        // it
        Mockito.lenient()
                .when(mockConfigService.getContraIndicatorConfigMap())
                .thenReturn(ciConfigMap);
    }

    @NotNull
    private static OauthCriConfig getMockCredentialIssuerConfig(MockServer mockServer)
            throws URISyntaxException {
        return OauthCriConfig.builder()
                .tokenUrl(new URI("http://localhost:" + mockServer.getPort() + "/token"))
                .credentialUrl(
                        new URI("http://localhost:" + mockServer.getPort() + "/credential/issue"))
                .authorizeUrl(new URI("http://localhost:" + mockServer.getPort() + "/authorize"))
                .clientId(IPV_CORE_CLIENT_ID)
                .signingKey(CRI_SIGNING_PRIVATE_KEY_JWK)
                .encryptionKey(CRI_RSA_ENCRYPTION_PUBLIC_JWK)
                .componentId(TEST_ISSUER)
                .clientCallbackUrl(
                        URI.create(
                                "https://identity.staging.account.gov.uk/credential-issuer/callback?id=drivingLicence"))
                .requiresApiKey(true)
                .requiresAdditionalEvidence(false)
                .build();
    }
}
