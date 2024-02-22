package uk.gov.di.ipv.core.processasynccricredential.pact.f2fCri;

import au.com.dius.pact.consumer.MessagePactBuilder;
import au.com.dius.pact.consumer.MockServer;
import au.com.dius.pact.consumer.dsl.PactDslJsonRootValue;
import au.com.dius.pact.consumer.junit.MockServerConfig;
import au.com.dius.pact.consumer.junit5.PactConsumerTestExt;
import au.com.dius.pact.consumer.junit5.PactTestFor;
import au.com.dius.pact.consumer.junit5.ProviderType;
import au.com.dius.pact.core.model.annotations.Pact;
import au.com.dius.pact.core.model.messaging.Message;
import au.com.dius.pact.core.model.messaging.MessagePact;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.SignedJWT;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.domain.ContraIndicatorConfig;
import uk.gov.di.ipv.core.library.dto.OauthCriConfig;
import uk.gov.di.ipv.core.library.exceptions.VerifiableCredentialException;
import uk.gov.di.ipv.core.library.helpers.FixedTimeJWTClaimsVerifier;
import uk.gov.di.ipv.core.library.pacttesthelpers.PactJwtBuilder;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.verifiablecredential.validator.VerifiableCredentialJwtValidator;
import uk.gov.di.ipv.core.processasynccricredential.domain.SuccessAsyncCriResponse;
import uk.gov.di.ipv.core.processasynccricredential.dto.CriResponseMessageDto;
import uk.gov.di.ipv.core.processasynccricredential.helpers.JwtParser;

import java.net.URI;
import java.net.URISyntaxException;
import java.text.ParseException;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Date;
import java.util.List;
import java.util.Map;

import static au.com.dius.pact.consumer.dsl.LambdaDsl.newJsonBody;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.processasynccricredential.helpers.AsyncCriResponseHelper.getAsyncResponseMessage;

@Disabled("PACT tests should not be run in build pipelines at this time")
@ExtendWith(PactConsumerTestExt.class)
@ExtendWith(MockitoExtension.class)
@PactTestFor(providerName = "F2fCriProvider")
@MockServerConfig(hostInterface = "localhost", port = "1234")
public class ContractTest {
    public static final String FULL_ADDRESS = "fullAddress";
    private final JwtParser jwtParser = new JwtParser();
    private final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final String TEST_ISSUER = "dummyF2fComponentId";
    private static final String TEST_USER = "test-subject";
    private static final String TEST_OAUTH_STATE = "f5f0d4d1-b937-4abe-b379-8269f600ad44";
    private static final String IPV_CORE_CLIENT_ID = "ipv-core";
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
                      "typ": "JWT",
                      "alg": "ES256"
                    }
                    """;
    // 2099-01-01 00:00:00 is 4070908800 in epoch seconds
    private static final String VALID_F2F_VC_WITH_PASSPORT_BODY =
            """
                      {
                       "sub": "test-subject",
                       "aud": "dummyF2fComponentId",
                       "nbf": 4070908800,
                       "iss": "dummyF2fComponentId",
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
                                   "value": "Kenneth"
                                 },
                                 {
                                   "type": "FamilyName",
                                   "value": "Decerqueira"
                                 }
                               ]
                             }
                           ],
                           "birthDate": [
                             {
                               "value": "1965-07-08"
                             }
                           ],
                           "socialSecurityRecord": [],
                           "emailAddress": "dev-platform-testing@digital.cabinet-office.gov.uk",
                           "passport": [
                             {
                               "expiryDate": "2030-01-01",
                               "documentNumber": "321654987"
                             }
                           ]
                         },
                         "evidence": [
                           {
                             "checkDetails": [
                               {
                                 "identityCheckPolicy": "published",
                                 "checkMethod": "vcrypt"
                               },
                               {
                                 "biometricVerificationProcessLevel": 3,
                                 "checkMethod": "bvr"
                               }
                             ],
                             "validityScore": 2,
                             "verificationScore": 3,
                             "strengthScore": 4,
                             "type": "IdentityCheck",
                             "txn": "eda339dd-aa83-495c-a4d4-75021e9415f9"
                           }
                         ]
                       },
                       "jti": "test-jti"
                     }
                    """;

    private static final String FAILED_F2F_VC_WITH_PASSPORT_BODY =
            """
              {
               "sub": "test-subject",
               "aud": "dummyF2fComponentId",
               "nbf": 4070908800,
               "iss": "dummyF2fComponentId",
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
                           "value": "Kenneth"
                         },
                         {
                           "type": "FamilyName",
                           "value": "Decerqueira"
                         }
                       ]
                     }
                   ],
                   "birthDate": [
                     {
                       "value": "1965-07-08"
                     }
                   ],
                   "socialSecurityRecord": [],
                   "emailAddress": "dev-platform-testing@digital.cabinet-office.gov.uk",
                   "passport": [
                     {
                       "expiryDate": "2030-01-01",
                       "documentNumber": "321654987"
                     }
                   ]
                 },
                 "evidence": [
                   {
                     "failedCheckDetails": [
                       {
                         "identityCheckPolicy": "published",
                         "checkMethod": "vcrypt"
                       },
                       {
                         "biometricVerificationProcessLevel": 3,
                         "checkMethod": "bvr"
                       }
                     ],
                     "validityScore": 0,
                     "verificationScore": 3,
                     "strengthScore": 4,
                     "type": "IdentityCheck",
                     "txn": "eda339dd-aa83-495c-a4d4-75021e9415f9"
                   }
                 ]
               },
               "jti": "test-jti"
             }
            """;

    private static final String FAILED_F2F_WITH_CIS_VC_WITH_PASSPORT_BODY =
            """
              {
               "sub": "test-subject",
               "aud": "dummyF2fComponentId",
               "nbf": 4070908800,
               "iss": "dummyF2fComponentId",
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
                           "value": "Kenneth"
                         },
                         {
                           "type": "FamilyName",
                           "value": "Decerqueira"
                         }
                       ]
                     }
                   ],
                   "birthDate": [
                     {
                       "value": "1965-07-08"
                     }
                   ],
                   "socialSecurityRecord": [],
                   "emailAddress": "dev-platform-testing@digital.cabinet-office.gov.uk",
                   "passport": [
                     {
                       "expiryDate": "2030-01-01",
                       "documentNumber": "321654987"
                     }
                   ]
                 },
                 "evidence": [
                   {
                     "failedCheckDetails": [
                       {
                         "identityCheckPolicy": "published",
                         "checkMethod": "vcrypt"
                       },
                       {
                         "biometricVerificationProcessLevel": 3,
                         "checkMethod": "bvr"
                       }
                     ],
                     "validityScore": 0,
                     "verificationScore": 3,
                     "strengthScore": 4,
                     "ci": ["D14"],
                     "type": "IdentityCheck",
                     "txn": "eda339dd-aa83-495c-a4d4-75021e9415f9"
                   }
                 ]
               },
               "jti": "test-jti"
             }
            """;
    private static final String VALID_F2F_VC_WITH_DVLA_BODY =
            """
                    {
                      "sub": "test-subject",
                      "aud": "dummyF2fComponentId",
                      "nbf": 4070908800,
                      "iss": "dummyF2fComponentId",
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
                                  "value": "Alice"
                                },
                                {
                                  "type": "GivenName",
                                  "value": "Jane"
                                },
                                {
                                  "type": "FamilyName",
                                  "value": "Parker"
                                }
                              ]
                            }
                          ],
                          "birthDate": [
                            {
                              "value": "1970-01-01"
                            }
                          ],
                          "socialSecurityRecord": [],
                          "emailAddress": "dev-platform-testing@digital.cabinet-office.gov.uk",
                          "drivingPermit": [
                            {
                              "expiryDate": "2032-02-02",
                              "issuedBy": "DVLA",
                              "personalNumber": "PARKE710112PBFGA",
                              "issueDate": "2005-02-02",
                              "fullAddress": "dummyTestAddress"
                            }
                          ]
                        },
                        "evidence": [
                          {
                            "checkDetails": [
                              {
                                "identityCheckPolicy": "published",
                                "checkMethod": "vcrypt"
                              },
                              {
                                "biometricVerificationProcessLevel": 3,
                                "checkMethod": "bvr"
                              }
                            ],
                            "validityScore": 2,
                            "verificationScore": 3,
                            "strengthScore": 3,
                            "type": "IdentityCheck",
                            "txn": "9daf6fa8-bbed-4854-8f7a-e635121ab4d7"
                          }
                        ]
                      },
                      "jti": "urn:uuid:811b7c3b-c0e0-4520-903c-3c6b97c734fc"
                    }
                    """;
    private static final String VALID_F2F_VC_WITH_EU_DL_BODY =
            """
                    {
                      "sub": "test-subject",
                      "aud": "dummyF2fComponentId",
                      "nbf": 4070908800,
                      "iss": "dummyF2fComponentId",
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
                                  "value": "Alice"
                                },
                                {
                                  "type": "GivenName",
                                  "value": "Jane"
                                },
                                {
                                  "type": "FamilyName",
                                  "value": "Parker"
                                }
                              ]
                            }
                          ],
                          "birthDate": [
                            {
                              "value": "1970-01-01"
                            }
                          ],
                          "socialSecurityRecord": [],
                          "emailAddress": "dev-platform-testing@digital.cabinet-office.gov.uk",
                          "drivingPermit": [
                             {
                               "personalNumber": "DOE99751010AL9OD",
                               "expiryDate": "2022-02-02",
                               "issueDate": "2012-02-02",
                               "issuingCountry": "DE",
                               "issuedBy": "Landratsamt"
                             }
                           ]
                        },
                        "evidence": [
                          {
                            "checkDetails": [
                              {
                                "identityCheckPolicy": "published",
                                "checkMethod": "vcrypt"
                              },
                              {
                                "biometricVerificationProcessLevel": 3,
                                "checkMethod": "bvr"
                              }
                            ],
                            "validityScore": 2,
                            "verificationScore": 3,
                            "strengthScore": 3,
                            "type": "IdentityCheck",
                            "txn": "9daf6fa8-bbed-4854-8f7a-e635121ab4d7"
                          }
                        ]
                      },
                      "jti": "urn:uuid:811b7c3b-c0e0-4520-903c-3c6b97c734fc"
                    }
                    """;

    private static final String VALID_F2F_VC_WITH_EEA_CARD_BODY =
            """
                    {
                      "sub": "test-subject",
                      "aud": "dummyF2fComponentId",
                      "nbf": 4070908800,
                      "iss": "dummyF2fComponentId",
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
                                  "value": "Saul"
                                },
                                {
                                  "type": "FamilyName",
                                  "value": "Goodman"
                                }
                              ]
                            }
                          ],
                          "birthDate": [
                            {
                              "value": "1970-01-01"
                            }
                          ],
                          "socialSecurityRecord": [],
                          "emailAddress": "dev-platform-testing@digital.cabinet-office.gov.uk",
                          "idCard": [
                             {
                               "icaoIssuerCode": "NLD",
                               "documentNumber": "SPEC12031",
                               "expiryDate": "2031-08-02",
                               "issueDate": "2021-08-02"
                             }
                           ]
                        },
                        "evidence": [
                          {
                            "checkDetails": [
                              {
                                "identityCheckPolicy": "published",
                                "checkMethod": "vcrypt"
                              },
                              {
                                "biometricVerificationProcessLevel": 3,
                                "checkMethod": "bvr"
                              }
                            ],
                            "validityScore": 2,
                            "verificationScore": 3,
                            "strengthScore": 4,
                            "type": "IdentityCheck",
                            "txn": "9daf6fa8-bbed-4854-8f7a-e635121ab4d7"
                          }
                        ]
                      },
                      "jti": "urn:uuid:811b7c3b-c0e0-4520-903c-3c6b97c734fc"
                    }
                    """;

    private static final String VALID_F2F_VC_WITH_BRP_BODY =
            """
                    {
                      "sub": "test-subject",
                      "aud": "dummyF2fComponentId",
                      "nbf": 4070908800,
                      "iss": "dummyF2fComponentId",
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
                                  "value": "Saul"
                                },
                                {
                                  "type": "FamilyName",
                                  "value": "Goodman"
                                }
                              ]
                            }
                          ],
                          "birthDate": [
                            {
                              "value": "1970-01-01"
                            }
                          ],
                          "socialSecurityRecord": [],
                          "emailAddress": "dev-platform-testing@digital.cabinet-office.gov.uk",
                          "residencePermit": [
                              {
                                "icaoIssuerCode": "UTO",
                                "documentType": "CR",
                                "documentNumber": "AX66K69P2",
                                "expiryDate": "2030-07-13"
                              }
                            ]
                        },
                        "evidence": [
                          {
                            "checkDetails": [
                              {
                                "identityCheckPolicy": "published",
                                "checkMethod": "vcrypt"
                              },
                              {
                                "biometricVerificationProcessLevel": 3,
                                "checkMethod": "bvr"
                              }
                            ],
                            "validityScore": 2,
                            "verificationScore": 3,
                            "strengthScore": 4,
                            "type": "IdentityCheck",
                            "txn": "9daf6fa8-bbed-4854-8f7a-e635121ab4d7"
                          }
                        ]
                      },
                      "jti": "urn:uuid:811b7c3b-c0e0-4520-903c-3c6b97c734fc"
                    }
                    """;

    // If we generate the signature in code it will be different each time, so we need to generate a
    // valid signature (using https://jwt.io works well) and record it here so the PACT file doesn't
    // change each time we run the tests.
    private static final String VALID_F2F_VC_PASSPORT_SIGNATURE =
            "CAMtOsXoWJiNWG5JPOqRoP8Ry-3hyCRqR1VodFVSbNzsXXTn2xjQXK1J3PIxfc8ZOd9IV-TZC3gZvGty-I9CKw";
    private static final String FAILED_F2F_VC_PASSPORT_SIGNATURE =
            "ugRXqbY74OWMzfbg_ShPSzY7HTOU8FoWfuxIY5fBSvnVRsgmdt_TC5ut5qLA_ZKl_lVXK7cY8-fidkOdvXZkPw";
    private static final String FAILED_F2F_WITH_CIS_VC_PASSPORT_SIGNATURE =
            "MtebBKK3vJrjwPGAqVCctBVmVDNY_4zegZ7M7VCRdEbb4njBW5Y1KNvtAh0VWPu-_Km_pnyLns0N0S5OtUB8Iw";
    private static final String VALID_F2F_VC_DL_SIGNATURE =
            "mGzhvuAmWet6HDAd-09iOxlXm8Zy2EbEOa-9zzklTdCxUkt3hdS4gXEMBDzhpCmZkPWSU4iknQ_O9xhBYBAVTg";
    private static final String VALID_F2F_VC_EU_DL_SIGNATURE =
            "zIvcoq6mDP6kBapT3O4tY3GKD40Kh7mOyQvzMZuLYHoYzdifXPgSuooZpbaJ8nrPmq8oLXm6oH10QA7Pz3pt6w";
    private static final String VALID_F2F_VC_EEA_SIGNATURE =
            "UDdqVolY0NN0Vi6dlAzuIvELLHXECjcNxlWUkhBa4etEQN_2jiVJnS5lk_QPlQ_XGyH2Vf-xObGwUTUtCKcWzw";
    private static final String VALID_F2F_VC_BRP_SIGNATURE =
            "v4JoFixil7YHheTshqdLMCoXCElCuduQ4MREvkWhq3_QrsQ8QimmZ3MsGayrKt_nhPYjUUNixWJYpyWRTqGyLg";
    public static final String DOCUMENT_NUMBER = "documentNumber";
    public static final String ICAO_ISSUER_CODE = "icaoIssuerCode";
    public static final String RESIDENCE_PERMIT = "residencePermit";
    public static final String NAME_PARTS = "nameParts";
    public static final String BIRTH_DATE = "birthDate";
    public static final String NAME = "name";
    public static final String EXPIRY_DATE = "expiryDate";
    public static final String DOCUMENT_TYPE = "documentType";
    public static final String VALUE = "value";
    public static final String NAME_TYPE = "type";
    public static final String ISSUE_DATE = "issueDate";
    public static final String ISSUED_BY = "issuedBy";
    public static final String PERSONAL_NUMBER = "personalNumber";
    public static final String DRIVING_PERMIT = "drivingPermit";
    public static final String CREDENTIAL_SUBJECT = "credentialSubject";
    public static final String VC = "vc";
    public static final String PASSPORT = "passport";
    @Mock private ConfigService mockConfigService;

    @Pact(provider = "F2fCriProvider", consumer = "IpvCoreBack")
    public MessagePact f2fMessageContainsValidPassportCredential(MessagePactBuilder builder)
            throws JsonProcessingException {
        return builder.given("test-subject is a valid subject")
                .given("dummyF2fComponentId is a valid issuer")
                .given("dummyF2fComponentId is a valid audience")
                .given("https://vocab.account.gov.uk/v1/credentialJWT contains a VC")
                .given("VC emailAddress is dev-platform-testing@digital.cabinet-office.gov.uk")
                .given("VC givenName is Kenneth")
                .given("VC familyName is Decerqueira")
                .given("VC birthDate is 1965-07-08")
                .given("VC passport documentNumber is 321654987")
                .given("VC passport expiryDate is 2030-01-01")
                .given("VC evidence validityScore is 2")
                .given("VC evidence verificationScore is 3")
                .given("VC evidence strengthScore is 4")
                .given("VC evidence type is IdentityCheck")
                .given("VC evidence txn is eda339dd-aa83-495c-a4d4-75021e9415f9")
                .given("VC jti is test-jti")
                .expectsToReceive("A valid F2F CRI message from SQS")
                .withContent(
                        newJsonBody(
                                        (body) -> {
                                            var jwtBuilder =
                                                    new PactJwtBuilder(
                                                            VALID_VC_HEADER,
                                                            VALID_F2F_VC_WITH_PASSPORT_BODY,
                                                            VALID_F2F_VC_PASSPORT_SIGNATURE);

                                            body.nullValue("error");
                                            body.stringValue("iss", "f2f");
                                            body.stringValue("sub", "test-subject");
                                            body.stringType(
                                                    "state",
                                                    "f5f0d4d1-b937-4abe-b379-8269f600ad44");
                                            body.nullValue("error_description");
                                            body.minMaxArrayLike(
                                                    "https://vocab.account.gov.uk/v1/credentialJWT",
                                                    1,
                                                    1,
                                                    PactDslJsonRootValue.stringMatcher(
                                                            jwtBuilder
                                                                    .buildRegexMatcherIgnoringSignature(),
                                                            jwtBuilder.buildJwt()),
                                                    1);
                                        })
                                .build())
                .toPact();
    }

    @Test
    @PactTestFor(
            pactMethod = "f2fMessageContainsValidPassportCredential",
            providerType = ProviderType.ASYNCH)
    void testF2fMessageReturnsIssuedPassportCredential(
            List<Message> messageList, MockServer mockServer) throws URISyntaxException {
        VerifiableCredentialJwtValidator verifiableCredentialJwtValidator =
                new VerifiableCredentialJwtValidator(
                        mockConfigService,
                        ((exactMatchClaims, requiredClaims) ->
                                new FixedTimeJWTClaimsVerifier<>(
                                        exactMatchClaims,
                                        requiredClaims,
                                        Date.from(CURRENT_TIME.instant()))));

        var credentialIssuerConfig = getCredentialIssuerConfig(mockServer);

        for (Message message : messageList) {
            try {
                SuccessAsyncCriResponse asyncCriResponse =
                        ((SuccessAsyncCriResponse)
                                getAsyncResponseMessage(message.contentsAsString()));

                List<SignedJWT> parsedJwts =
                        jwtParser.parseVerifiableCredentialJWTs(
                                asyncCriResponse.getVerifiableCredentialJWTs());

                parsedJwts.forEach(
                        credential -> {
                            try {
                                verifiableCredentialJwtValidator.validate(
                                        credential, credentialIssuerConfig, TEST_USER);

                                JsonNode credentialSubject =
                                        objectMapper
                                                .readTree(credential.getJWTClaimsSet().toString())
                                                .get(VC)
                                                .get(CREDENTIAL_SUBJECT);

                                JsonNode nameParts =
                                        credentialSubject.get(NAME).get(0).get(NAME_PARTS);
                                JsonNode birthDateNode = credentialSubject.get(BIRTH_DATE).get(0);
                                JsonNode passportNode = credentialSubject.get(PASSPORT).get(0);

                                assertEquals("GivenName", nameParts.get(0).get(NAME_TYPE).asText());
                                assertEquals(
                                        "FamilyName", nameParts.get(1).get(NAME_TYPE).asText());

                                assertEquals("Kenneth", nameParts.get(0).get(VALUE).asText());
                                assertEquals("Decerqueira", nameParts.get(1).get(VALUE).asText());

                                assertEquals("2030-01-01", passportNode.get(EXPIRY_DATE).asText());
                                assertEquals(
                                        "321654987", passportNode.get(DOCUMENT_NUMBER).asText());

                                assertEquals("1965-07-08", birthDateNode.get(VALUE).asText());

                            } catch (VerifiableCredentialException
                                    | ParseException
                                    | JsonProcessingException e) {
                                throw new RuntimeException(e);
                            }
                        });
            } catch (JsonProcessingException | ParseException e) {
                throw new RuntimeException(e);
            }
        }
    }

    @Pact(provider = "F2fCriProvider", consumer = "IpvCoreBack")
    public MessagePact f2fMessageContainsFailedPassportCredential(MessagePactBuilder builder)
            throws JsonProcessingException {
        return builder.given("test-subject is a valid subject")
                .given("dummyF2fComponentId is a valid issuer")
                .given("dummyF2fComponentId is a valid audience")
                .given("https://vocab.account.gov.uk/v1/credentialJWT contains a VC")
                .given("VC type is [\"VerifiableCredential\", \"IdentityCheckCredential\"]")
                .given("VC emailAddress is dev-platform-testing@digital.cabinet-office.gov.uk")
                .given("VC givenName is Kenneth")
                .given("VC familyName is Decerqueira")
                .given("VC birthDate is 1965-07-08")
                .given("VC passport documentNumber is 321654987")
                .given("VC passport expiryDate is 2030-01-01")
                .given("VC evidence contains failedCheckDetails")
                .given("VC evidence validityScore is 0")
                .given("VC evidence verificationScore is 3")
                .given("VC evidence strengthScore is 4")
                .given("VC evidence type is IdentityCheck")
                .given("VC evidence txn is eda339dd-aa83-495c-a4d4-75021e9415f9")
                .given("VC jti is test-jti")
                .expectsToReceive("A valid F2F CRI message from SQS")
                .withContent(
                        newJsonBody(
                                        (body) -> {
                                            var jwtBuilder =
                                                    new PactJwtBuilder(
                                                            VALID_VC_HEADER,
                                                            FAILED_F2F_VC_WITH_PASSPORT_BODY,
                                                            FAILED_F2F_VC_PASSPORT_SIGNATURE);

                                            body.nullValue("error");
                                            body.stringValue("iss", "f2f");
                                            body.stringValue("sub", "test-subject");
                                            body.stringType(
                                                    "state",
                                                    "f5f0d4d1-b937-4abe-b379-8269f600ad44");
                                            body.nullValue("error_description");
                                            body.minArrayLike(
                                                    "https://vocab.account.gov.uk/v1/credentialJWT",
                                                    1,
                                                    PactDslJsonRootValue.stringMatcher(
                                                            jwtBuilder
                                                                    .buildRegexMatcherIgnoringSignature(),
                                                            jwtBuilder.buildJwt()),
                                                    1);
                                        })
                                .build())
                .toPact();
    }

    @Test
    @PactTestFor(
            pactMethod = "f2fMessageContainsFailedPassportCredential",
            providerType = ProviderType.ASYNCH)
    void testF2fMessageReturnsFailedPassportCredential(
            List<Message> messageList, MockServer mockServer) throws URISyntaxException {
        VerifiableCredentialJwtValidator verifiableCredentialJwtValidator =
                new VerifiableCredentialJwtValidator(
                        mockConfigService,
                        ((exactMatchClaims, requiredClaims) ->
                                new FixedTimeJWTClaimsVerifier<>(
                                        exactMatchClaims,
                                        requiredClaims,
                                        Date.from(CURRENT_TIME.instant()))));

        var credentialIssuerConfig = getCredentialIssuerConfig(mockServer);

        for (Message message : messageList) {
            try {
                SuccessAsyncCriResponse asyncCriResponse =
                        ((SuccessAsyncCriResponse)
                                getAsyncResponseMessage(message.contentsAsString()));

                List<SignedJWT> parsedJwts =
                        jwtParser.parseVerifiableCredentialJWTs(
                                asyncCriResponse.getVerifiableCredentialJWTs());

                parsedJwts.forEach(
                        credential -> {
                            try {
                                verifiableCredentialJwtValidator.validate(
                                        credential, credentialIssuerConfig, TEST_USER);

                                JsonNode credentialSubject =
                                        objectMapper
                                                .readTree(credential.getJWTClaimsSet().toString())
                                                .get(VC)
                                                .get(CREDENTIAL_SUBJECT);

                                JsonNode evidence =
                                        objectMapper
                                                .readTree(credential.getJWTClaimsSet().toString())
                                                .get(VC)
                                                .get("evidence")
                                                .get(0);

                                JsonNode nameParts =
                                        credentialSubject.get(NAME).get(0).get(NAME_PARTS);
                                JsonNode birthDateNode = credentialSubject.get(BIRTH_DATE).get(0);
                                JsonNode passportNode = credentialSubject.get(PASSPORT).get(0);

                                assertNotNull(evidence.get("failedCheckDetails").get(0));
                                assertEquals("0", evidence.get("validityScore").asText());
                                assertEquals("3", evidence.get("verificationScore").asText());
                                assertEquals("4", evidence.get("strengthScore").asText());

                                assertEquals("GivenName", nameParts.get(0).get(NAME_TYPE).asText());
                                assertEquals(
                                        "FamilyName", nameParts.get(1).get(NAME_TYPE).asText());

                                assertEquals("Kenneth", nameParts.get(0).get(VALUE).asText());
                                assertEquals("Decerqueira", nameParts.get(1).get(VALUE).asText());

                                assertEquals("2030-01-01", passportNode.get(EXPIRY_DATE).asText());
                                assertEquals(
                                        "321654987", passportNode.get(DOCUMENT_NUMBER).asText());

                                assertEquals("1965-07-08", birthDateNode.get(VALUE).asText());

                            } catch (VerifiableCredentialException
                                    | ParseException
                                    | JsonProcessingException e) {
                                throw new RuntimeException(e);
                            }
                        });
            } catch (JsonProcessingException | ParseException e) {
                throw new RuntimeException(e);
            }
        }
    }

    @Pact(provider = "F2fCriProvider", consumer = "IpvCoreBack")
    public MessagePact f2fMessageContainsFailedWithCiPassportCredential(MessagePactBuilder builder)
            throws JsonProcessingException {
        return builder.given("test-subject is a valid subject")
                .given("dummyF2fComponentId is a valid issuer")
                .given("dummyF2fComponentId is a valid audience")
                .given("https://vocab.account.gov.uk/v1/credentialJWT contains a VC")
                .given("VC type is [\"VerifiableCredential\", \"IdentityCheckCredential\"]")
                .given("VC emailAddress is dev-platform-testing@digital.cabinet-office.gov.uk")
                .given("VC givenName is Kenneth")
                .given("VC familyName is Decerqueira")
                .given("VC birthDate is 1965-07-08")
                .given("VC passport documentNumber is 321654987")
                .given("VC passport expiryDate is 2030-01-01")
                .given("VC evidence contains failedCheckDetails")
                .given("VC evidence ci is D14")
                .given("VC evidence validityScore is 2")
                .given("VC evidence verificationScore is 3")
                .given("VC evidence strengthScore is 4")
                .given("VC evidence type is IdentityCheck")
                .given("VC evidence txn is eda339dd-aa83-495c-a4d4-75021e9415f9")
                .given("VC jti is test-jti")
                .expectsToReceive("A valid F2F CRI message from SQS")
                .withContent(
                        newJsonBody(
                                        (body) -> {
                                            var jwtBuilder =
                                                    new PactJwtBuilder(
                                                            VALID_VC_HEADER,
                                                            FAILED_F2F_WITH_CIS_VC_WITH_PASSPORT_BODY,
                                                            FAILED_F2F_WITH_CIS_VC_PASSPORT_SIGNATURE);

                                            body.nullValue("error");
                                            body.stringValue("iss", "f2f");
                                            body.stringValue("sub", "test-subject");
                                            body.stringType(
                                                    "state",
                                                    "f5f0d4d1-b937-4abe-b379-8269f600ad44");
                                            body.nullValue("error_description");
                                            body.minArrayLike(
                                                    "https://vocab.account.gov.uk/v1/credentialJWT",
                                                    1,
                                                    PactDslJsonRootValue.stringMatcher(
                                                            jwtBuilder
                                                                    .buildRegexMatcherIgnoringSignature(),
                                                            jwtBuilder.buildJwt()),
                                                    1);
                                        })
                                .build())
                .toPact();
    }

    @Test
    @PactTestFor(
            pactMethod = "f2fMessageContainsFailedWithCiPassportCredential",
            providerType = ProviderType.ASYNCH)
    void testF2fMessageReturnsFailedPassportCredentialWithCi(
            List<Message> messageList, MockServer mockServer) throws URISyntaxException {
        VerifiableCredentialJwtValidator verifiableCredentialJwtValidator =
                new VerifiableCredentialJwtValidator(
                        mockConfigService,
                        ((exactMatchClaims, requiredClaims) ->
                                new FixedTimeJWTClaimsVerifier<>(
                                        exactMatchClaims,
                                        requiredClaims,
                                        Date.from(CURRENT_TIME.instant()))));

        when(mockConfigService.getContraIndicatorConfigMap())
                .thenReturn(Map.of("D14", new ContraIndicatorConfig("D14", 4, -3, "1")));

        var credentialIssuerConfig = getCredentialIssuerConfig(mockServer);

        for (Message message : messageList) {
            try {
                SuccessAsyncCriResponse asyncCriResponse =
                        ((SuccessAsyncCriResponse)
                                getAsyncResponseMessage(message.contentsAsString()));

                List<SignedJWT> parsedJwts =
                        jwtParser.parseVerifiableCredentialJWTs(
                                asyncCriResponse.getVerifiableCredentialJWTs());

                parsedJwts.forEach(
                        credential -> {
                            try {
                                verifiableCredentialJwtValidator.validate(
                                        credential, credentialIssuerConfig, TEST_USER);

                                JsonNode credentialSubject =
                                        objectMapper
                                                .readTree(credential.getJWTClaimsSet().toString())
                                                .get(VC)
                                                .get(CREDENTIAL_SUBJECT);

                                JsonNode evidence =
                                        objectMapper
                                                .readTree(credential.getJWTClaimsSet().toString())
                                                .get(VC)
                                                .get("evidence")
                                                .get(0);

                                JsonNode nameParts =
                                        credentialSubject.get(NAME).get(0).get(NAME_PARTS);
                                JsonNode birthDateNode = credentialSubject.get(BIRTH_DATE).get(0);
                                JsonNode passportNode = credentialSubject.get(PASSPORT).get(0);

                                assertNotNull(evidence.get("failedCheckDetails").get(0));
                                assertEquals("D14", evidence.get("ci").get(0).asText());
                                assertEquals("0", evidence.get("validityScore").asText());
                                assertEquals("3", evidence.get("verificationScore").asText());
                                assertEquals("4", evidence.get("strengthScore").asText());

                                assertEquals("GivenName", nameParts.get(0).get(NAME_TYPE).asText());
                                assertEquals(
                                        "FamilyName", nameParts.get(1).get(NAME_TYPE).asText());

                                assertEquals("Kenneth", nameParts.get(0).get(VALUE).asText());
                                assertEquals("Decerqueira", nameParts.get(1).get(VALUE).asText());

                                assertEquals("2030-01-01", passportNode.get(EXPIRY_DATE).asText());
                                assertEquals(
                                        "321654987", passportNode.get(DOCUMENT_NUMBER).asText());

                                assertEquals("1965-07-08", birthDateNode.get(VALUE).asText());

                            } catch (VerifiableCredentialException
                                    | ParseException
                                    | JsonProcessingException e) {
                                throw new RuntimeException(e);
                            }
                        });
            } catch (JsonProcessingException | ParseException e) {
                throw new RuntimeException(e);
            }
        }
    }

    @Pact(provider = "F2fCriProvider", consumer = "IpvCoreBack")
    public MessagePact f2fMessageContainsValidDrivingLicenseCredential(MessagePactBuilder builder)
            throws Exception {
        return builder.given("dummyApiKey is a valid api key")
                .given("dummyAccessToken is a valid access token")
                .given("test-subject is a valid subject")
                .given("dummyF2fComponentId is a valid issuer")
                .given("dummyF2fComponentId is a valid audience")
                .given("VC emailAddress is dev-platform-testing@digital.cabinet-office.gov.uk")
                .given("VC givenName is Alice")
                .given("VC middle name is Jane")
                .given("VC familyName is Parker")
                .given("VC birthDate is 1970-01-01")
                .given("VC driving license personalNumber is PARKE710112PBFGA")
                .given("VC driving license expiryDate is 2032-02-02")
                .given("VC driving license issueDate is 2005-02-02")
                .given("VC driving license issuedBy is DVLA")
                .given("VC driving license fullAddress is dummyTestAddress")
                .given("VC evidence validityScore is 2")
                .given("VC evidence verificationScore is 3")
                .given("VC evidence strengthScore is 3")
                .given("VC evidence type is IdentityCheck")
                .given("VC evidence txn is eda339dd-aa83-495c-a4d4-75021e9415f9")
                .given("VC jti is test-jti")
                .expectsToReceive("A valid F2F CRI with Driving License")
                .withContent(
                        newJsonBody(
                                        (body) -> {
                                            var jwtBuilder =
                                                    new PactJwtBuilder(
                                                            VALID_VC_HEADER,
                                                            VALID_F2F_VC_WITH_DVLA_BODY,
                                                            VALID_F2F_VC_DL_SIGNATURE);

                                            body.nullValue("error");
                                            body.stringValue("iss", "f2f");
                                            body.stringValue("sub", "test-subject");
                                            body.stringType(
                                                    "state",
                                                    "f5f0d4d1-b937-4abe-b379-8269f600ad44");
                                            body.nullValue("error_description");
                                            body.minArrayLike(
                                                    "https://vocab.account.gov.uk/v1/credentialJWT",
                                                    1,
                                                    PactDslJsonRootValue.stringMatcher(
                                                            jwtBuilder
                                                                    .buildRegexMatcherIgnoringSignature(),
                                                            jwtBuilder.buildJwt()),
                                                    1);
                                        })
                                .build())
                .toPact();
    }

    @Test
    @PactTestFor(
            pactMethod = "f2fMessageContainsValidDrivingLicenseCredential",
            providerType = ProviderType.ASYNCH)
    void testF2fMessageReturnsIssuedDrivingLicenseCredential(
            List<Message> messageList, MockServer mockServer) throws URISyntaxException {
        VerifiableCredentialJwtValidator verifiableCredentialJwtValidator =
                new VerifiableCredentialJwtValidator(
                        mockConfigService,
                        ((exactMatchClaims, requiredClaims) ->
                                new FixedTimeJWTClaimsVerifier<>(
                                        exactMatchClaims,
                                        requiredClaims,
                                        Date.from(CURRENT_TIME.instant()))));

        var credentialIssuerConfig = getCredentialIssuerConfig(mockServer);

        for (Message message : messageList) {
            try {
                SuccessAsyncCriResponse asyncCriResponse =
                        ((SuccessAsyncCriResponse)
                                getAsyncResponseMessage(message.contentsAsString()));

                List<SignedJWT> parsedJwts =
                        jwtParser.parseVerifiableCredentialJWTs(
                                asyncCriResponse.getVerifiableCredentialJWTs());

                parsedJwts.forEach(
                        credential -> {
                            try {
                                verifiableCredentialJwtValidator.validate(
                                        credential, credentialIssuerConfig, TEST_USER);

                                JsonNode credentialSubject =
                                        objectMapper
                                                .readTree(credential.getJWTClaimsSet().toString())
                                                .get(VC)
                                                .get(CREDENTIAL_SUBJECT);

                                JsonNode nameParts =
                                        credentialSubject.get(NAME).get(0).get(NAME_PARTS);
                                JsonNode birthDateNode = credentialSubject.get(BIRTH_DATE).get(0);
                                JsonNode drivingLicenseNode =
                                        credentialSubject.get(DRIVING_PERMIT).get(0);

                                assertEquals("GivenName", nameParts.get(0).get(NAME_TYPE).asText());
                                assertEquals("GivenName", nameParts.get(1).get(NAME_TYPE).asText());
                                assertEquals(
                                        "FamilyName", nameParts.get(2).get(NAME_TYPE).asText());

                                assertEquals("Alice", nameParts.get(0).get(VALUE).asText());
                                assertEquals("Jane", nameParts.get(1).get(VALUE).asText());
                                assertEquals("Parker", nameParts.get(2).get(VALUE).asText());

                                assertEquals(
                                        "2032-02-02", drivingLicenseNode.get(EXPIRY_DATE).asText());
                                assertEquals(
                                        "2005-02-02", drivingLicenseNode.get(ISSUE_DATE).asText());
                                assertEquals(
                                        "dummyTestAddress",
                                        drivingLicenseNode.get(FULL_ADDRESS).asText());
                                assertEquals("DVLA", drivingLicenseNode.get(ISSUED_BY).asText());
                                assertEquals(
                                        "PARKE710112PBFGA",
                                        drivingLicenseNode.get(PERSONAL_NUMBER).asText());

                                assertEquals("1970-01-01", birthDateNode.get(VALUE).asText());

                            } catch (VerifiableCredentialException
                                    | ParseException
                                    | JsonProcessingException e) {
                                throw new RuntimeException(e);
                            }
                        });
            } catch (JsonProcessingException | ParseException e) {
                throw new RuntimeException(e);
            }
        }
    }

    @Pact(provider = "F2fCriProvider", consumer = "IpvCoreBack")
    public MessagePact f2fMessageContainsValidEuDrivingLicenseCredential(MessagePactBuilder builder)
            throws Exception {
        return builder.given("dummyApiKey is a valid api key")
                .given("dummyAccessToken is a valid access token")
                .given("test-subject is a valid subject")
                .given("dummyF2fComponentId is a valid issuer")
                .given("dummyF2fComponentId is a valid audience")
                .given("VC emailAddress is dev-platform-testing@digital.cabinet-office.gov.uk")
                .given("VC givenName is Alice")
                .given("VC middle name is Jane")
                .given("VC familyName is Parker")
                .given("VC birthDate is 1970-01-01")
                .given("VC driving license personalNumber is DOE99751010AL9OD")
                .given("VC driving license expiryDate is 2022-02-02")
                .given("VC driving license issueDate is 2012-02-02")
                .given("VC driving license issuingCountry is DE")
                .given("VC driving license issuedBy is Landratsamt")
                .given("VC evidence validityScore is 2")
                .given("VC evidence verificationScore is 3")
                .given("VC evidence strengthScore is 3")
                .given("VC evidence type is IdentityCheck")
                .given("VC evidence txn is eda339dd-aa83-495c-a4d4-75021e9415f9")
                .given("VC jti is test-jti")
                .expectsToReceive("A valid F2F CRI with Driving License")
                .withContent(
                        newJsonBody(
                                        (body) -> {
                                            var jwtBuilder =
                                                    new PactJwtBuilder(
                                                            VALID_VC_HEADER,
                                                            VALID_F2F_VC_WITH_EU_DL_BODY,
                                                            VALID_F2F_VC_EU_DL_SIGNATURE);

                                            body.nullValue("error");
                                            body.stringValue("iss", "f2f");
                                            body.stringValue("sub", "test-subject");
                                            body.stringType(
                                                    "state",
                                                    "f5f0d4d1-b937-4abe-b379-8269f600ad44");
                                            body.nullValue("error_description");
                                            body.minArrayLike(
                                                    "https://vocab.account.gov.uk/v1/credentialJWT",
                                                    1,
                                                    PactDslJsonRootValue.stringMatcher(
                                                            jwtBuilder
                                                                    .buildRegexMatcherIgnoringSignature(),
                                                            jwtBuilder.buildJwt()),
                                                    1);
                                        })
                                .build())
                .toPact();
    }

    @Test
    @PactTestFor(
            pactMethod = "f2fMessageContainsValidEuDrivingLicenseCredential",
            providerType = ProviderType.ASYNCH)
    void testF2fMessageReturnsIssuedEuDrivingLicenseCredential(
            List<Message> messageList, MockServer mockServer) throws URISyntaxException {
        VerifiableCredentialJwtValidator verifiableCredentialJwtValidator =
                new VerifiableCredentialJwtValidator(
                        mockConfigService,
                        ((exactMatchClaims, requiredClaims) ->
                                new FixedTimeJWTClaimsVerifier<>(
                                        exactMatchClaims,
                                        requiredClaims,
                                        Date.from(CURRENT_TIME.instant()))));

        var credentialIssuerConfig = getCredentialIssuerConfig(mockServer);

        for (Message message : messageList) {
            try {
                SuccessAsyncCriResponse asyncCriResponse =
                        ((SuccessAsyncCriResponse)
                                getAsyncResponseMessage(message.contentsAsString()));

                List<SignedJWT> parsedJwts =
                        jwtParser.parseVerifiableCredentialJWTs(
                                asyncCriResponse.getVerifiableCredentialJWTs());

                parsedJwts.forEach(
                        credential -> {
                            try {
                                verifiableCredentialJwtValidator.validate(
                                        credential, credentialIssuerConfig, TEST_USER);

                                JsonNode credentialSubject =
                                        objectMapper
                                                .readTree(credential.getJWTClaimsSet().toString())
                                                .get(VC)
                                                .get(CREDENTIAL_SUBJECT);

                                JsonNode nameParts =
                                        credentialSubject.get(NAME).get(0).get(NAME_PARTS);
                                JsonNode birthDateNode = credentialSubject.get(BIRTH_DATE).get(0);
                                JsonNode drivingLicenseNode =
                                        credentialSubject.get(DRIVING_PERMIT).get(0);

                                assertEquals("GivenName", nameParts.get(0).get(NAME_TYPE).asText());
                                assertEquals("GivenName", nameParts.get(1).get(NAME_TYPE).asText());
                                assertEquals(
                                        "FamilyName", nameParts.get(2).get(NAME_TYPE).asText());

                                assertEquals("Alice", nameParts.get(0).get(VALUE).asText());
                                assertEquals("Jane", nameParts.get(1).get(VALUE).asText());
                                assertEquals("Parker", nameParts.get(2).get(VALUE).asText());

                                assertEquals(
                                        "2022-02-02", drivingLicenseNode.get(EXPIRY_DATE).asText());
                                assertEquals(
                                        "2012-02-02", drivingLicenseNode.get(ISSUE_DATE).asText());
                                assertEquals(
                                        "Landratsamt", drivingLicenseNode.get(ISSUED_BY).asText());
                                assertEquals(
                                        "DOE99751010AL9OD",
                                        drivingLicenseNode.get(PERSONAL_NUMBER).asText());

                                assertEquals("1970-01-01", birthDateNode.get(VALUE).asText());

                            } catch (VerifiableCredentialException
                                    | ParseException
                                    | JsonProcessingException e) {
                                throw new RuntimeException(e);
                            }
                        });
            } catch (JsonProcessingException | ParseException e) {
                throw new RuntimeException(e);
            }
        }
    }

    @Pact(provider = "F2fCriProvider", consumer = "IpvCoreBack")
    public MessagePact f2fMessageContainsValidEeaCardCredential(MessagePactBuilder builder)
            throws Exception {
        return builder.given("dummyApiKey is a valid api key")
                .given("dummyAccessToken is a valid access token")
                .given("test-subject is a valid subject")
                .given("dummyF2fComponentId is a valid issuer")
                .given("dummyF2fComponentId is a valid audience")
                .given("VC emailAddress is dev-platform-testing@digital.cabinet-office.gov.uk")
                .given("VC givenName is Saul")
                .given("VC familyName is Goodman")
                .given("VC birthDate is 1970-01-01")
                .given("VC EEA card icaoIssuerCode is NLD")
                .given("VC EEA card documentNumber is SPEC12031")
                .given("VC EEA card expiryDate is 2031-08-02")
                .given("VC EEA card issueDate is 2021-08-02")
                .given("VC evidence validityScore is 2")
                .given("VC evidence verificationScore is 3")
                .given("VC evidence strengthScore is 4")
                .given("VC evidence type is IdentityCheck")
                .given("VC evidence txn is eda339dd-aa83-495c-a4d4-75021e9415f9")
                .given("VC jti is test-jti")
                .expectsToReceive("A valid F2F CRI with EEA Card")
                .withContent(
                        newJsonBody(
                                        (body) -> {
                                            var jwtBuilder =
                                                    new PactJwtBuilder(
                                                            VALID_VC_HEADER,
                                                            VALID_F2F_VC_WITH_EEA_CARD_BODY,
                                                            VALID_F2F_VC_EEA_SIGNATURE);

                                            body.nullValue("error");
                                            body.stringValue("iss", "f2f");
                                            body.stringValue("sub", "test-subject");
                                            body.stringType(
                                                    "state",
                                                    "f5f0d4d1-b937-4abe-b379-8269f600ad44");
                                            body.nullValue("error_description");
                                            body.minArrayLike(
                                                    "https://vocab.account.gov.uk/v1/credentialJWT",
                                                    1,
                                                    PactDslJsonRootValue.stringMatcher(
                                                            jwtBuilder
                                                                    .buildRegexMatcherIgnoringSignature(),
                                                            jwtBuilder.buildJwt()),
                                                    1);
                                        })
                                .build())
                .toPact();
    }

    @Test
    @PactTestFor(
            pactMethod = "f2fMessageContainsValidEeaCardCredential",
            providerType = ProviderType.ASYNCH)
    void testF2fMessageReturnsIssuedEeaCardCredential(
            List<Message> messageList, MockServer mockServer) throws URISyntaxException {
        VerifiableCredentialJwtValidator verifiableCredentialJwtValidator =
                new VerifiableCredentialJwtValidator(
                        mockConfigService,
                        ((exactMatchClaims, requiredClaims) ->
                                new FixedTimeJWTClaimsVerifier<>(
                                        exactMatchClaims,
                                        requiredClaims,
                                        Date.from(CURRENT_TIME.instant()))));

        var credentialIssuerConfig = getCredentialIssuerConfig(mockServer);

        for (Message message : messageList) {
            try {
                SuccessAsyncCriResponse asyncCriResponse =
                        ((SuccessAsyncCriResponse)
                                getAsyncResponseMessage(message.contentsAsString()));

                List<SignedJWT> parsedJwts =
                        jwtParser.parseVerifiableCredentialJWTs(
                                asyncCriResponse.getVerifiableCredentialJWTs());

                parsedJwts.forEach(
                        credential -> {
                            try {
                                verifiableCredentialJwtValidator.validate(
                                        credential, credentialIssuerConfig, TEST_USER);

                                JsonNode credentialSubject =
                                        objectMapper
                                                .readTree(credential.getJWTClaimsSet().toString())
                                                .get(VC)
                                                .get(CREDENTIAL_SUBJECT);

                                JsonNode nameParts =
                                        credentialSubject.get(NAME).get(0).get(NAME_PARTS);
                                JsonNode birthDateNode = credentialSubject.get(BIRTH_DATE).get(0);
                                JsonNode idCardNode = credentialSubject.get("idCard").get(0);

                                assertEquals("GivenName", nameParts.get(0).get(NAME_TYPE).asText());
                                assertEquals(
                                        "FamilyName", nameParts.get(1).get(NAME_TYPE).asText());

                                assertEquals("Saul", nameParts.get(0).get(VALUE).asText());
                                assertEquals("Goodman", nameParts.get(1).get(VALUE).asText());

                                assertEquals("2031-08-02", idCardNode.get(EXPIRY_DATE).asText());
                                assertEquals("2021-08-02", idCardNode.get(ISSUE_DATE).asText());
                                assertEquals("NLD", idCardNode.get(ICAO_ISSUER_CODE).asText());
                                assertEquals("SPEC12031", idCardNode.get(DOCUMENT_NUMBER).asText());

                                assertEquals("1970-01-01", birthDateNode.get(VALUE).asText());
                            } catch (VerifiableCredentialException
                                    | ParseException
                                    | JsonProcessingException e) {
                                throw new RuntimeException(e);
                            }
                        });
            } catch (JsonProcessingException | ParseException e) {
                throw new RuntimeException(e);
            }
        }
    }

    @Pact(provider = "F2fCriProvider", consumer = "IpvCoreBack")
    public MessagePact f2fMessageContainsValidBrpCredential(MessagePactBuilder builder)
            throws Exception {
        return builder.given("dummyApiKey is a valid api key")
                .given("dummyAccessToken is a valid access token")
                .given("test-subject is a valid subject")
                .given("dummyF2fComponentId is a valid issuer")
                .given("dummyF2fComponentId is a valid audience")
                .given("VC emailAddress is dev-platform-testing@digital.cabinet-office.gov.uk")
                .given("VC givenName is Saul")
                .given("VC familyName is Goodman")
                .given("VC birthDate is 1970-01-01")
                .given("VC BRP icaoIssuerCode is UTO")
                .given("VC BRP documentType is CR")
                .given("VC BRP documentNumber is AX66K69P2")
                .given("VC BRP expiryDate is 2030-07-13")
                .given("VC evidence validityScore is 2")
                .given("VC evidence verificationScore is 3")
                .given("VC evidence strengthScore is 4")
                .given("VC evidence type is IdentityCheck")
                .given("VC evidence txn is eda339dd-aa83-495c-a4d4-75021e9415f9")
                .given("VC jti is test-jti")
                .expectsToReceive("A valid F2F CRI with BRP Document")
                .withContent(
                        newJsonBody(
                                        (body) -> {
                                            var jwtBuilder =
                                                    new PactJwtBuilder(
                                                            VALID_VC_HEADER,
                                                            VALID_F2F_VC_WITH_BRP_BODY,
                                                            VALID_F2F_VC_BRP_SIGNATURE);

                                            body.nullValue("error");
                                            body.stringValue("iss", "f2f");
                                            body.stringValue("sub", "test-subject");
                                            body.stringType(
                                                    "state",
                                                    "f5f0d4d1-b937-4abe-b379-8269f600ad44");
                                            body.nullValue("error_description");
                                            body.minArrayLike(
                                                    "https://vocab.account.gov.uk/v1/credentialJWT",
                                                    1,
                                                    PactDslJsonRootValue.stringMatcher(
                                                            jwtBuilder
                                                                    .buildRegexMatcherIgnoringSignature(),
                                                            jwtBuilder.buildJwt()),
                                                    1);
                                        })
                                .build())
                .toPact();
    }

    @Test
    @PactTestFor(
            pactMethod = "f2fMessageContainsValidBrpCredential",
            providerType = ProviderType.ASYNCH)
    void testF2fMessageReturnsIssuedBrpCredential(List<Message> messageList, MockServer mockServer)
            throws URISyntaxException, ParseException {
        VerifiableCredentialJwtValidator verifiableCredentialJwtValidator =
                new VerifiableCredentialJwtValidator(
                        mockConfigService,
                        ((exactMatchClaims, requiredClaims) ->
                                new FixedTimeJWTClaimsVerifier<>(
                                        exactMatchClaims,
                                        requiredClaims,
                                        Date.from(CURRENT_TIME.instant()))));

        var credentialIssuerConfig = getCredentialIssuerConfig(mockServer);

        for (Message message : messageList) {
            try {
                SuccessAsyncCriResponse asyncCriResponse =
                        ((SuccessAsyncCriResponse)
                                getAsyncResponseMessage(message.contentsAsString()));

                List<SignedJWT> parsedJwts =
                        jwtParser.parseVerifiableCredentialJWTs(
                                asyncCriResponse.getVerifiableCredentialJWTs());

                parsedJwts.forEach(
                        credential -> {
                            try {
                                verifiableCredentialJwtValidator.validate(
                                        credential, credentialIssuerConfig, TEST_USER);

                                JsonNode credentialSubject =
                                        objectMapper
                                                .readTree(credential.getJWTClaimsSet().toString())
                                                .get(VC)
                                                .get(CREDENTIAL_SUBJECT);

                                JsonNode nameParts =
                                        credentialSubject.get(NAME).get(0).get(NAME_PARTS);
                                JsonNode birthDateNode = credentialSubject.get(BIRTH_DATE).get(0);
                                JsonNode residencePermitNode =
                                        credentialSubject.get(RESIDENCE_PERMIT).get(0);

                                assertEquals("GivenName", nameParts.get(0).get(NAME_TYPE).asText());
                                assertEquals(
                                        "FamilyName", nameParts.get(1).get(NAME_TYPE).asText());

                                assertEquals("Saul", nameParts.get(0).get(VALUE).asText());
                                assertEquals("Goodman", nameParts.get(1).get(VALUE).asText());

                                assertEquals(
                                        "2030-07-13",
                                        residencePermitNode.get(EXPIRY_DATE).asText());
                                assertEquals(
                                        "AX66K69P2",
                                        residencePermitNode.get(DOCUMENT_NUMBER).asText());
                                assertEquals(
                                        "UTO", residencePermitNode.get(ICAO_ISSUER_CODE).asText());
                                assertEquals("CR", residencePermitNode.get(DOCUMENT_TYPE).asText());

                                assertEquals("1970-01-01", birthDateNode.get(VALUE).asText());

                            } catch (VerifiableCredentialException
                                    | ParseException
                                    | JsonProcessingException e) {
                                throw new RuntimeException(e);
                            }
                        });
            } catch (JsonProcessingException e) {
                throw new RuntimeException(e);
            }
        }
    }

    @NotNull
    private static OauthCriConfig getCredentialIssuerConfig(MockServer mockServer)
            throws URISyntaxException {
        return OauthCriConfig.builder()
                .tokenUrl(new URI("http://localhost:" + mockServer.getPort() + "/token"))
                .credentialUrl(new URI("http://localhost:" + mockServer.getPort() + "/credential"))
                .authorizeUrl(new URI("http://localhost:" + mockServer.getPort() + "/authorize"))
                .clientId(IPV_CORE_CLIENT_ID)
                .signingKey(CRI_SIGNING_PRIVATE_KEY_JWK)
                .encryptionKey(CRI_RSA_ENCRYPTION_PUBLIC_JWK)
                .componentId(TEST_ISSUER)
                .clientCallbackUrl(
                        URI.create(
                                "https://identity.staging.account.gov.uk/credential-issuer/callback?id=f2f"))
                .requiresApiKey(true)
                .requiresAdditionalEvidence(false)
                .build();
    }

    private String createSuccessTestEvent(String jwtBody, String jwtSignature)
            throws JsonProcessingException {
        final CriResponseMessageDto criResponseMessageDto =
                new CriResponseMessageDto(
                        "f2f",
                        TEST_USER,
                        TEST_OAUTH_STATE,
                        List.of(
                                new PactJwtBuilder(VALID_VC_HEADER, jwtBody, jwtSignature)
                                        .buildJwt()),
                        null,
                        null);
        return OBJECT_MAPPER.writeValueAsString(criResponseMessageDto);
    }
}
