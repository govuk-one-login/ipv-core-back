package uk.gov.di.ipv.core.processcricallback.pact.dcmawCri;

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
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeType;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.token.AccessTokenType;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
import uk.gov.di.ipv.core.library.domain.ContraIndicatorConfig;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.dto.CriCallbackRequest;
import uk.gov.di.ipv.core.library.dto.OauthCriConfig;
import uk.gov.di.ipv.core.library.exceptions.VerifiableCredentialException;
import uk.gov.di.ipv.core.library.helpers.FixedTimeJWTClaimsVerifier;
import uk.gov.di.ipv.core.library.helpers.SecureTokenHelper;
import uk.gov.di.ipv.core.library.persistence.item.CriOAuthSessionItem;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.verifiablecredential.validator.VerifiableCredentialJwtValidator;
import uk.gov.di.ipv.core.processcricallback.exception.CriApiException;
import uk.gov.di.ipv.core.processcricallback.pact.PactJwtIgnoreSignatureBodyBuilder;
import uk.gov.di.ipv.core.processcricallback.service.CriApiService;

import java.net.URI;
import java.net.URISyntaxException;
import java.sql.Date;
import java.text.ParseException;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import static au.com.dius.pact.consumer.dsl.LambdaDsl.newJsonBody;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.greaterThan;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

@Disabled("PACT tests should not be run in build pipelines at this time")
@ExtendWith(PactConsumerTestExt.class)
@ExtendWith(MockitoExtension.class)
@PactTestFor(providerName = "DcmawCriProvider")
@MockServerConfig(hostInterface = "localhost", port = "1234")
class ContractTest {
    private static final String TEST_USER = "test-subject";
    private static final String TEST_ISSUER = "dummyDcmawComponentId";
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

    private static final String CLIENT_ASSERTION_HEADER = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9";
    private static final String CLIENT_ASSERTION_BODY =
            "eyJpc3MiOiJpcHYtY29yZSIsInN1YiI6Imlwdi1jb3JlIiwiYXVkIjoiZHVtbXlEY21hd0NvbXBvbmVudElkIiwiZXhwIjo0MDcwOTA5NzAwLCJqdGkiOiJTY25GNGRHWHRoWllYU181azg1T2JFb1NVMDRXLUgzcWFfcDZucHYyWlVZIn0";
    // Signature generated using JWT.io
    private static final String CLIENT_ASSERTION_SIGNATURE =
            "42XAVWAIET_BI7FpFQHVIaoW3yRx9yt8HGgMRFMJdxjBey6tQLDRM_04cddot-pNCqYk8x6TueAOdHFsy6N9_A";

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
    // From DCMAW-410-AC1
    private static final String VALID_DVLA_VC_BODY =
            """
            {
              "sub": "test-subject",
              "iss": "dummyDcmawComponentId",
              "nbf": 4070908800,
              "exp": 4070909400,
              "vc": {
                "@context": [
                  "https://www.w3.org/2018/credentials/v1",
                  "https://vocab.account.gov.uk/contexts/identity-v1.jsonld"
                ],
                "type": [
                  "VerifiableCredential",
                  "IdentityCheckCredential"
                ],
                "credentialSubject": {
                  "name": [
                    {
                      "nameParts": [
                        {
                          "value": "Joe",
                          "type": "GivenName"
                        },
                        {
                          "value": "Shmoe",
                          "type": "GivenName"
                        },
                        {
                          "value": "Doe The Ball",
                          "type": "FamilyName"
                        }
                      ]
                    }
                  ],
                  "birthDate": [
                    {
                      "value": "1985-02-08"
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
                      "postalCode": "CH1 1AQ",
                      "addressCountry": null
                    }
                  ],
                  "drivingPermit": [
                    {
                      "personalNumber": "DOE99802085J99FG",
                      "expiryDate": "2023-01-18",
                      "issueNumber": null,
                      "issuedBy": "DVLA",
                      "issueDate": "2022-05-29",
                      "fullAddress": "WHATEVER STREET, WIRRAL, CH1 1AQ"
                    }
                  ]
                },
                "evidence": [
                  {
                    "type": "IdentityCheck",
                    "txn": "ea2feefe-45a3-4a29-923f-604cd4017ec0",
                    "strengthScore": 3,
                    "validityScore": 2,
                    "activityHistoryScore": 1,
                    "checkDetails": [
                      {
                        "checkMethod": "vri",
                        "identityCheckPolicy": "published",
                        "activityFrom": "2022-05-29"
                      },
                      {
                        "checkMethod": "bvr",
                        "biometricVerificationProcessLevel": 3
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
    private static final String VALID_DVLA_VC_SIGNATURE =
            "MPwaYUsf5HBJ7Gp5oq5TJ71l1B2zfUXOrDeIXpotsnJpWsHonGV11yralObDqFM5UXCCrqemyCLQPWZ6z6seFg";

    // 2099-01-01 00:00:00 is 4070908800 in epoch seconds
    // Based on DCMAW-410-AC1 with given names removed
    private static final String VALID_DVLA_VC_NO_GIVEN_NAME_BODY =
            """
            {
              "sub": "test-subject",
              "iss": "dummyDcmawComponentId",
              "nbf": 4070908800,
              "exp": 4070909400,
              "vc": {
                "@context": [
                  "https://www.w3.org/2018/credentials/v1",
                  "https://vocab.account.gov.uk/contexts/identity-v1.jsonld"
                ],
                "type": [
                  "VerifiableCredential",
                  "IdentityCheckCredential"
                ],
                "credentialSubject": {
                  "name": [
                    {
                      "nameParts": [
                        {
                          "value": "Doe The Ball",
                          "type": "FamilyName"
                        }
                      ]
                    }
                  ],
                  "birthDate": [
                    {
                      "value": "1985-02-08"
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
                      "postalCode": "CH1 1AQ",
                      "addressCountry": null
                    }
                  ],
                  "drivingPermit": [
                    {
                      "personalNumber": "DOE99802085J99FG",
                      "expiryDate": "2023-01-18",
                      "issueNumber": null,
                      "issuedBy": "DVLA",
                      "issueDate": "2022-05-29",
                      "fullAddress": "WHATEVER STREET, WIRRAL, CH1 1AQ"
                    }
                  ]
                },
                "evidence": [
                  {
                    "type": "IdentityCheck",
                    "txn": "ea2feefe-45a3-4a29-923f-604cd4017ec0",
                    "strengthScore": 3,
                    "validityScore": 2,
                    "activityHistoryScore": 1,
                    "checkDetails": [
                      {
                        "checkMethod": "vri",
                        "identityCheckPolicy": "published",
                        "activityFrom": "2022-05-29"
                      },
                      {
                        "checkMethod": "bvr",
                        "biometricVerificationProcessLevel": 3
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
    private static final String VALID_DVLA_VC_NO_GIVEN_NAME_SIGNATURE =
            "iHsylWKOSdUv2bbCkKeU5yyQKNsuXiXSM7vcK3t7HFUnWKX--bAOwsw8_vOK84QeVhzOBy8u7RFR95kNF76OoQ";

    // 2099-01-01 00:00:00 is 4070908800 in epoch seconds
    // From DCMAW-5477-AC1
    private static final String FAILED_DVLA_VC_WITH_CI_BODY =
            """
            {
              "sub": "test-subject",
              "iss": "dummyDcmawComponentId",
              "nbf": 4070908800,
              "exp": 4070909400,
              "vc": {
                "@context": [
                  "https://www.w3.org/2018/credentials/v1",
                  "https://vocab.account.gov.uk/contexts/identity-v1.jsonld"
                ],
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
                      "V01"
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
              }
            }
            """;
    // If we generate the signature in code it will be different each time, so we need to generate a
    // valid signature (using https://jwt.io works well) and record it here so the PACT file doesn't
    // change each time we run the tests.
    private static final String FAILED_DVLA_VC_WITH_CI_SIGNATURE =
            "hURplyqcvd87w2tm76hDRlGxuBgGmmKC6o-h8IA0fz3uuTHCLLyhhpH6DvuHRtOUleTmNJ19tabUXZwT9vIFjQ";

    // 2099-01-01 00:00:00 is 4070908800 in epoch seconds
    // From DCMAW-1045-AC1
    private static final String FAILED_DVA_VC_NO_CI_BODY =
            """
            {
              "sub": "test-subject",
              "iss": "dummyDcmawComponentId",
              "nbf": 4070908800,
              "exp": 4070909400,
              "vc": {
                "@context": [
                  "https://www.w3.org/2018/credentials/v1",
                  "https://vocab.account.gov.uk/contexts/identity-v1.jsonld"
                ],
                "type": [
                  "VerifiableCredential",
                  "IdentityCheckCredential"
                ],
                "credentialSubject": {
                  "name": [
                    {
                      "nameParts": [
                        {
                          "value": "SARAH",
                          "type": "GivenName"
                        },
                        {
                          "value": "MEREDYTH",
                          "type": "GivenName"
                        },
                        {
                          "value": "MORGAN",
                          "type": "FamilyName"
                        }
                      ]
                    }
                  ],
                  "birthDate": [
                    {
                      "value": "1976-03-11"
                    }
                  ],
                  "deviceId": [
                    {
                      "value": "a3017511-b639-46ff-ab73-66e5ab0193c9"
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
                      "postalCode": "EH1 9GP",
                      "addressCountry": null
                    }
                  ],
                  "drivingPermit": [
                    {
                      "personalNumber": "MORGA753116SM9IJ",
                      "issueNumber": null,
                      "issuedBy": "DVA",
                      "issueDate": null,
                      "expiryDate": "2023-01-18",
                      "fullAddress": "122 BURNS CRESCENT EDINBURGH EH1 9GP"
                    }
                  ]
                },
                "evidence": [
                  {
                    "type": "IdentityCheck",
                    "txn": "bcd2346",
                    "strengthScore": 3,
                    "validityScore": 0,
                    "ci": [],
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
              }
            }
            """;
    // If we generate the signature in code it will be different each time, so we need to generate a
    // valid signature (using https://jwt.io works well) and record it here so the PACT file doesn't
    // change each time we run the tests.
    private static final String FAILED_DVA_VC_NO_CI_SIGNATURE =
            "Vfn6YWxKlwwdUeau-o_2Qx67ni2KMp6JPseqShrP9lcQskNaoBMpxFeae-Q5VAWlVcZlry9D9cU7tsrr6r2WYA";

    // 2099-01-01 00:00:00 is 4070908800 in epoch seconds
    // From DCMAW-1559-AC2
    private static final String VALID_DVA_VC_BODY =
            """
            {
              "sub": "test-subject",
              "iss": "dummyDcmawComponentId",
              "nbf": 4070908800,
              "exp": 4070909400,
              "vc": {
                "@context": [
                  "https://www.w3.org/2018/credentials/v1",
                  "https://vocab.account.gov.uk/contexts/identity-v1.jsonld"
                ],
                "type": [
                  "VerifiableCredential",
                  "IdentityCheckCredential"
                ],
                "credentialSubject": {
                  "name": [
                    {
                      "nameParts": [
                        {
                          "value": "OLGA",
                          "type": "GivenName"
                        },
                        {
                          "value": "A",
                          "type": "GivenName"
                        },
                        {
                          "value": "KULYK",
                          "type": "FamilyName"
                        }
                      ]
                    }
                  ],
                  "birthDate": [
                    {
                      "value": "1980-09-27"
                    }
                  ],
                  "deviceId": [
                    {
                      "value": "a3017511-b639-46ff-ab73-66e5ab0193c9"
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
                      "postalCode": null,
                      "addressCountry": null
                    }
                  ],
                  "drivingPermit": [
                    {
                      "expiryDate": "2028-02-20",
                      "issueDate": "2022-05-29",
                      "issueNumber": null,
                      "issuedBy": "DVA",
                      "personalNumber": "5823131861",
                      "fullAddress": null
                    }
                  ]
                },
                "evidence": [
                  {
                    "type": "IdentityCheck",
                    "txn": "1f9d73167e2166b707c6",
                    "strengthScore": 3,
                    "validityScore": 2,
                    "activityHistoryScore": 1,
                    "checkDetails": [
                      {
                        "checkMethod": "vri",
                        "identityCheckPolicy": "published",
                        "activityFrom": "2022-05-29"
                      },
                      {
                        "checkMethod": "bvr",
                        "biometricVerificationProcessLevel": 3
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
    private static final String VALID_DVA_VC_SIGNATURE =
            "KLX-9APfnyzb9BOxHW4Brrdgw3ovGA6DotcwXjGweCJeBUzczzE3FsBwN6HKueM9wabsSWQql7mOxRjHwRqf0A";

    // 2099-01-01 00:00:00 is 4070908800 in epoch seconds
    // From DCMAW-4733-AC1
    private static final String VALID_DRIVING_LICENCE_NO_ISSUER_VC_BODY =
            """
            {
              "sub": "test-subject",
              "iss": "dummyDcmawComponentId",
              "nbf": 4070908800,
              "exp": 4070909400,
              "vc": {
                "@context": [
                  "https://www.w3.org/2018/credentials/v1",
                  "https://vocab.account.gov.uk/contexts/identity-v1.jsonld"
                ],
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
                          "value": "Julian",
                          "type": "GivenName"
                        },
                        {
                          "value": "Boe",
                          "type": "FamilyName"
                        }
                      ]
                    }
                  ],
                  "birthDate": [
                    {
                      "value": "2011-11-28"
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
                      "postalCode": "CH62 2AQ",
                      "addressCountry": null
                    }
                  ],
                  "drivingPermit": [
                    {
                      "personalNumber": "BOEJJ861281TP9DH",
                      "expiryDate": "2028-08-07",
                      "issueNumber": null,
                      "issuedBy": null,
                      "issueDate": "2022-05-29",
                      "fullAddress": "102 ROVER ROAD, WIRRAL, CH62 2AQ"
                    }
                  ]
                },
                "evidence": [
                  {
                    "type": "IdentityCheck",
                    "txn": "ea2feefe-45a3-4a29-923f-604cd4017ec0",
                    "strengthScore": 3,
                    "validityScore": 2,
                    "activityHistoryScore": 1,
                    "checkDetails": [
                      {
                        "checkMethod": "vri",
                        "identityCheckPolicy": "published",
                        "activityFrom": "2022-05-29"
                      },
                      {
                        "checkMethod": "bvr",
                        "biometricVerificationProcessLevel": 3
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
    private static final String VALID_DRIVING_LICENCE_NO_ISSUER_VC_SIGNATURE =
            "TIe5PXJag0Mn9Oh_3Q6XuOWhwVfeiO-dvSabw9AZs3C2Md26cnX8eR_wu0MaMyD3w5MO_CzzBpYqxY-W6FmVhA";

    // 2099-01-01 00:00:00 is 4070908800 in epoch seconds
    // From DCMAW-3079-AC1
    private static final String VALID_UK_PASSPORT_VC_BODY =
            """
            {
              "sub": "test-subject",
              "iss": "dummyDcmawComponentId",
              "nbf": 4070908800,
              "exp": 4070909400,
              "vc": {
                "@context": [
                  "https://www.w3.org/2018/credentials/v1",
                  "https://vocab.account.gov.uk/contexts/identity-v1.jsonld"
                ],
                "credentialSubject": {
                  "name": [
                    {
                      "nameParts": [
                        {
                          "type": "GivenName",
                          "value": "ANNA"
                        },
                        {
                          "type": "GivenName",
                          "value": "NICHOLA"
                        },
                        {
                          "type": "FamilyName",
                          "value": "OTHER FORTYFOUR"
                        }
                      ]
                    }
                  ],
                  "birthDate": [
                    {
                      "value": "1960-01-01"
                    }
                  ],
                  "deviceId": [
                    {
                      "value": "a3017511-b639-46ff-ab73-66e5ab0193c9"
                    }
                  ],
                  "passport": [
                    {
                      "icaoIssuerCode": "GBR",
                      "documentNumber": "549364783",
                      "expiryDate": "2027-08-01"
                    }
                  ]
                },
                "type": [
                  "VerifiableCredential",
                  "IdentityCheckCredential"
                ],
                "evidence": [
                  {
                    "type": "IdentityCheck",
                    "txn": "biometricId",
                    "strengthScore": 4,
                    "validityScore": 3,
                    "checkDetails": [
                      {
                        "checkMethod": "vcrypt",
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
              }
            }
            """;
    // If we generate the signature in code it will be different each time, so we need to generate a
    // valid signature (using https://jwt.io works well) and record it here so the PACT file doesn't
    // change each time we run the tests.
    private static final String VALID_UK_PASSPORT_VC_SIGNATURE =
            "dnXc3avCGKj6XdKpGnNTgjH3lpRZotBSyzx4ttFksnaheiHExklxqGHc8ZNRdIJu0cpFyP-Dw6Bl5xO46nZCVA";

    // 2099-01-01 00:00:00 is 4070908800 in epoch seconds
    // From DCMAW-3146-AC1
    private static final String VALID_NLD_PASSPORT_VC_BODY =
            """
            {
              "sub": "test-subject",
              "iss": "dummyDcmawComponentId",
              "nbf": 4070908800,
              "exp": 4070909400,
              "vc": {
                "@context": [
                  "https://www.w3.org/2018/credentials/v1",
                  "https://vocab.account.gov.uk/contexts/identity-v1.jsonld"
                ],
                "credentialSubject": {
                  "name": [
                    {
                      "nameParts": [
                        {
                          "type": "GivenName",
                          "value": "OLGA"
                        },
                        {
                          "type": "GivenName",
                          "value": "ANATOLIYIVNA"
                        },
                        {
                          "type": "FamilyName",
                          "value": "KULYK"
                        }
                      ]
                    }
                  ],
                  "birthDate": [
                    {
                      "value": "1980-09-27"
                    }
                  ],
                  "deviceId": [
                    {
                      "value": "78b34ead-6ef6-4af3-8cc6-dcaa8e95ad71"
                    }
                  ],
                  "passport": [
                    {
                      "icaoIssuerCode": "NLD",
                      "documentNumber": "NXC65LP76",
                      "expiryDate": "2026-04-01"
                    }
                  ]
                },
                "type": [
                  "VerifiableCredential",
                  "IdentityCheckCredential"
                ],
                "evidence": [
                  {
                    "type": "IdentityCheck",
                    "txn": "biometricId",
                    "strengthScore": 4,
                    "validityScore": 3,
                    "checkDetails": [
                      {
                        "checkMethod": "vcrypt",
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
              }
            }
            """;
    // If we generate the signature in code it will be different each time, so we need to generate a
    // valid signature (using https://jwt.io works well) and record it here so the PACT file doesn't
    // change each time we run the tests.
    private static final String VALID_NLD_PASSPORT_VC_SIGNATURE =
            "HaA5_LWPnyzxb4zfBYDq9FR9rJGt4_YAfSJ7wzyF90SpCxRh2QoMscmkmBSz60rPZMXMoXXv5sWx96fbJyzd0g";

    // 2099-01-01 00:00:00 is 4070908800 in epoch seconds
    // From DCMAW-3171-AC2
    private static final String FAILED_PASSPORT_VC_WITH_CI_BODY =
            """
            {
              "sub": "test-subject",
              "iss": "dummyDcmawComponentId",
              "nbf": 4070908800,
              "exp": 4070909400,
              "vc": {
                "@context": [
                  "https://www.w3.org/2018/credentials/v1",
                  "https://vocab.account.gov.uk/contexts/identity-v1.jsonld"
                ],
                "credentialSubject": {
                  "name": [
                    {
                      "nameParts": [
                        {
                          "type": "GivenName",
                          "value": "ANNA"
                        },
                        {
                          "type": "GivenName",
                          "value": "NICHOLA"
                        },
                        {
                          "type": "FamilyName",
                          "value": "OTHER FORTYFOUR"
                        }
                      ]
                    }
                  ],
                  "birthDate": [
                    {
                      "value": "1960-01-01"
                    }
                  ],
                  "deviceId": [
                    {
                      "value": "a3017511-b639-46ff-ab73-66e5ab0193c9"
                    }
                  ],
                  "passport": [
                    {
                      "icaoIssuerCode": "GBR",
                      "documentNumber": "549364783",
                      "expiryDate": "2027-08-01"
                    }
                  ]
                },
                "type": [
                  "VerifiableCredential",
                  "IdentityCheckCredential"
                ],
                "evidence": [
                  {
                    "type": "IdentityCheck",
                    "txn": "biometricId",
                    "strengthScore": 4,
                    "validityScore": 0,
                    "ci": [
                      "V01"
                    ],
                    "failedCheckDetails": [
                      {
                        "checkMethod": "vcrypt",
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
              }
            }
            """;
    // If we generate the signature in code it will be different each time, so we need to generate a
    // valid signature (using https://jwt.io works well) and record it here so the PACT file doesn't
    // change each time we run the tests.
    private static final String FAILED_PASSPORT_VC_WITH_CI_SIGNATURE =
            "FZRxr03o7njVxKgUafUwSqbvbZtWNhmObEP7rHVoGcoWglBryD-Ghkn5gZ9AwqNVN8J4VpRIu2olij6TIiVq2A";

    // 2099-01-01 00:00:00 is 4070908800 in epoch seconds
    // From DCMAW-5176-AC1
    private static final String VALID_BRP_VC_BODY =
            """
            {
              "sub": "test-subject",
              "iss": "dummyDcmawComponentId",
              "nbf": 4070908800,
              "exp": 4070909400,
              "vc": {
                "@context": [
                  "https://www.w3.org/2018/credentials/v1",
                  "https://vocab.account.gov.uk/contexts/identity-v1.jsonld"
                ],
                "credentialSubject": {
                  "name": [
                    {
                      "nameParts": [
                        {
                          "type": "GivenName",
                          "value": "LATEFAMFOUR"
                        },
                        {
                          "type": "FamilyName",
                          "value": "LATEFAMLASTFOUR"
                        }
                      ]
                    }
                  ],
                  "birthDate": [
                    {
                      "value": "1980-01-01"
                    }
                  ],
                  "residencePermit": [
                    {
                      "icaoIssuerCode": "GBR",
                      "documentNumber": "ZR8016200",
                      "expiryDate": "2024-02-25",
                      "documentType": "IR"
                    }
                  ],
                  "deviceId": [
                    {
                      "value": "7d8f0d3c-6a0a-4298-afe5-0cf23633618c"
                    }
                  ]
                },
                "type": [
                  "VerifiableCredential",
                  "IdentityCheckCredential"
                ],
                "evidence": [
                  {
                    "type": "IdentityCheck",
                    "txn": "bcd2346",
                    "strengthScore": 4,
                    "validityScore": 3,
                    "checkDetails": [
                      {
                        "checkMethod": "vcrypt",
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
              }
            }
            """;
    // If we generate the signature in code it will be different each time, so we need to generate a
    // valid signature (using https://jwt.io works well) and record it here so the PACT file doesn't
    // change each time we run the tests.
    private static final String VALID_BRP_VC_SIGNATURE =
            "9CWqNbNL9ypAU0nD9mtNnu3uYInfyBxFybk0Cymj38axQfN-UPDpepwgNHkR9ebEGGoIy4dW3SPzjzENddAt2w";

    // 2099-01-01 00:00:00 is 4070908800 in epoch seconds
    // From DCMAW-5175-AC1
    private static final String FAILED_BRP_VC_BODY =
            """
            {
              "sub": "test-subject",
              "iss": "dummyDcmawComponentId",
              "nbf": 4070908800,
              "exp": 4070909400,
              "vc": {
                "@context": [
                  "https://www.w3.org/2018/credentials/v1",
                  "https://vocab.account.gov.uk/contexts/identity-v1.jsonld"
                ],
                "credentialSubject": {
                  "name": [
                    {
                      "nameParts": [
                        {
                          "type": "GivenName",
                          "value": "LATEFAMFOUR"
                        },
                        {
                          "type": "FamilyName",
                          "value": "LATEFAMLASTFOUR"
                        }
                      ]
                    }
                  ],
                  "birthDate": [
                    {
                      "value": "1980-01-01"
                    }
                  ],
                  "residencePermit": [
                    {
                      "icaoIssuerCode": "GBR",
                      "documentNumber": "ZR8016200",
                      "expiryDate": "2024-02-25",
                      "documentType": "IR"
                    }
                  ],
                  "deviceId": [
                    {
                      "value": "7d8f0d3c-6a0a-4298-afe5-0cf23633618c"
                    }
                  ]
                },
                "type": [
                  "VerifiableCredential",
                  "IdentityCheckCredential"
                ],
                "evidence": [
                  {
                    "type": "IdentityCheck",
                    "txn": "bcd2346",
                    "strengthScore": 4,
                    "validityScore": 0,
                    "ci": [
                      "V01"
                    ],
                    "failedCheckDetails": [
                      {
                        "checkMethod": "vcrypt",
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
              }
            }
            """;
    // If we generate the signature in code it will be different each time, so we need to generate a
    // valid signature (using https://jwt.io works well) and record it here so the PACT file doesn't
    // change each time we run the tests.
    private static final String FAILED_BRP_VC_SIGNATURE =
            "hF24S4veyQQONjKl9brU5fkJb-uQro7khveIt20NtqYavO6_inquM5YkOI-jTtGkC-vej2kous5pLRFoXGDm1g";

    // 2099-01-01 00:00:00 is 4070908800 in epoch seconds
    // From DCMAW-5176-AC1
    private static final String VALID_BRC_VC_BODY =
            """
            {
              "sub": "test-subject",
              "iss": "dummyDcmawComponentId",
              "nbf": 4070908800,
              "exp": 4070909400,
              "vc": {
                "@context": [
                  "https://www.w3.org/2018/credentials/v1",
                  "https://vocab.account.gov.uk/contexts/identity-v1.jsonld"
                ],
                "credentialSubject": {
                  "name": [
                    {
                      "nameParts": [
                        {
                          "type": "GivenName",
                          "value": "LATEFAMFOUR"
                        },
                        {
                          "type": "FamilyName",
                          "value": "LATEFAMLASTFOUR"
                        }
                      ]
                    }
                  ],
                  "birthDate": [
                    {
                      "value": "1980-01-01"
                    }
                  ],
                  "residencePermit": [
                    {
                      "icaoIssuerCode": "GBR",
                      "documentNumber": "ZR8016200",
                      "expiryDate": "2024-02-25",
                      "documentType": "CR"
                    }
                  ],
                  "deviceId": [
                    {
                      "value": "7d8f0d3c-6a0a-4298-afe5-0cf23633618c"
                    }
                  ]
                },
                "type": [
                  "VerifiableCredential",
                  "IdentityCheckCredential"
                ],
                "evidence": [
                  {
                    "type": "IdentityCheck",
                    "txn": "bcd2346",
                    "strengthScore": 4,
                    "validityScore": 3,
                    "checkDetails": [
                      {
                        "checkMethod": "vcrypt",
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
              }
            }
            """;
    // If we generate the signature in code it will be different each time, so we need to generate a
    // valid signature (using https://jwt.io works well) and record it here so the PACT file doesn't
    // change each time we run the tests.
    private static final String VALID_BRC_VC_SIGNATURE =
            "XHDMYWyiTJyBwZ2Za3PXRro7g0ggO_wDCLWXw8ukxrW5gE7wWz-ClBg_8oph_8QrbQBTArV5zkOmP2iCNMCknA";

    // 2099-01-01 00:00:00 is 4070908800 in epoch seconds
    // From DCMAW-5175-AC2
    private static final String FAILED_BRC_VC_BODY =
            """
            {
              "sub": "test-subject",
              "iss": "dummyDcmawComponentId",
              "nbf": 4070908800,
              "exp": 4070909400,
              "vc": {
                "@context": [
                  "https://www.w3.org/2018/credentials/v1",
                  "https://vocab.account.gov.uk/contexts/identity-v1.jsonld"
                ],
                "credentialSubject": {
                  "name": [
                    {
                      "nameParts": [
                        {
                          "type": "GivenName",
                          "value": "LATEFAMFOUR"
                        },
                        {
                          "type": "FamilyName",
                          "value": "LATEFAMLASTFOUR"
                        }
                      ]
                    }
                  ],
                  "birthDate": [
                    {
                      "value": "1980-01-01"
                    }
                  ],
                  "residencePermit": [
                    {
                      "icaoIssuerCode": "GBR",
                      "documentNumber": "ZR8016200",
                      "expiryDate": "2024-02-25",
                      "documentType": "CR"
                    }
                  ],
                  "deviceId": [
                    {
                      "value": "7d8f0d3c-6a0a-4298-afe5-0cf23633618c"
                    }
                  ]
                },
                "type": [
                  "VerifiableCredential",
                  "IdentityCheckCredential"
                ],
                "evidence": [
                  {
                    "type": "IdentityCheck",
                    "txn": "bcd2346",
                    "strengthScore": 4,
                    "validityScore": 0,
                    "ci": [],
                    "failedCheckDetails": [
                      {
                        "checkMethod": "vcrypt",
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
              }
            }
            """;
    // If we generate the signature in code it will be different each time, so we need to generate a
    // valid signature (using https://jwt.io works well) and record it here so the PACT file doesn't
    // change each time we run the tests.
    private static final String FAILED_BRC_VC_SIGNATURE =
            "77iM911qVdFEzBmfDI_M6GP62jq51laUj0LyK5ISwWWioDuciwi4aZji6yVsjk-SsZsckt6EOVBlUQ0RhFPRuA";

    @Mock private ConfigService mockConfigService;
    @Mock private JWSSigner mockSigner;
    @Mock private SecureTokenHelper mockSecureTokenHelper;

    @Pact(provider = "DcmawCriProvider", consumer = "IpvCoreBack")
    public RequestResponsePact validRequestReturnsValidAccessToken(PactDslWithProvider builder) {
        return builder.given("dummyAuthCode is a valid authorization code")
                .given("dummyApiKey is a valid api key")
                .given("dummyDcmawComponentId is the DCMAW CRI component ID")
                .given(
                        "DCMAW CRI uses CORE_BACK_SIGNING_PRIVATE_KEY_JWK to validate core signatures")
                .uponReceiving("Valid auth code")
                .path("/token")
                .method("POST")
                .body(
                        "client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer&code=dummyAuthCode&grant_type=authorization_code&redirect_uri=https%3A%2F%2Fidentity.staging.account.gov.uk%2Fcredential-issuer%2Fcallback%3Fid%3Ddcmaw&client_assertion="
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
                                        (body) -> {
                                            body.stringType("access_token");
                                            body.stringValue("token_type", "Bearer");
                                            body.integerType("expires_in");
                                        })
                                .build())
                .toPact();
    }

    @Test
    @PactTestFor(pactMethod = "validRequestReturnsValidAccessToken")
    void fetchAccessToken_whenCalledAgainstDcmawCri_retrievesAValidAccessToken(
            MockServer mockServer) throws URISyntaxException, JOSEException, CriApiException {
        // Arrange
        var credentialIssuerConfig = getMockCredentialIssuerConfig(mockServer);

        when(mockConfigService.getSsmParameter(ConfigurationVariable.JWT_TTL_SECONDS))
                .thenReturn("900");
        when(mockConfigService.getOauthCriConfig(any())).thenReturn(credentialIssuerConfig);
        when(mockConfigService.getCriPrivateApiKey(any())).thenReturn(PRIVATE_API_KEY);

        // Fix the signature here as mocking out the AWSKMS class inside the real signer would be
        // painful.
        when(mockSigner.sign(any(), any())).thenReturn(new Base64URL(CLIENT_ASSERTION_SIGNATURE));
        when(mockSigner.supportedJWSAlgorithms()).thenReturn(Set.of(JWSAlgorithm.ES256));
        when(mockSecureTokenHelper.generate())
                .thenReturn("ScnF4dGXthZYXS_5k85ObEoSU04W-H3qa_p6npv2ZUY");

        // We need to generate a fixed request, so we set the secure token and expiry to constant
        // values.
        var underTest =
                new CriApiService(
                        mockConfigService, mockSigner, mockSecureTokenHelper, CURRENT_TIME);

        // Act
        BearerAccessToken accessToken =
                underTest.fetchAccessToken(
                        getCallbackRequest("dummyAuthCode", credentialIssuerConfig),
                        getCriOAuthSessionItem());
        // Assert
        assertThat(accessToken.getType(), is(AccessTokenType.BEARER));
        assertThat(accessToken.getValue(), notNullValue());
        assertThat(accessToken.getLifetime(), greaterThan(0L));
    }

    @Pact(provider = "DcmawCriProvider", consumer = "IpvCoreBack")
    public RequestResponsePact invalidAuthCodeRequestReturns400(PactDslWithProvider builder) {
        return builder.given("dummyInvalidAuthCode is an invalid authorization code")
                .given("dummyApiKey is a valid api key")
                .given("dummyDcmawComponentId is the DCMAW CRI component ID")
                .given(
                        "DCMAW CRI uses CORE_BACK_SIGNING_PRIVATE_KEY_JWK to validate core signatures")
                .uponReceiving("Invalid auth code")
                .path("/token")
                .method("POST")
                .body(
                        "client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer&code=dummyInvalidAuthCode&grant_type=authorization_code&redirect_uri=https%3A%2F%2Fidentity.staging.account.gov.uk%2Fcredential-issuer%2Fcallback%3Fid%3Ddcmaw&client_assertion="
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
    void fetchAccessToken_whenCalledAgainstDcmawCriWithInvalidAuthCode_throwsAnException(
            MockServer mockServer) throws URISyntaxException, JOSEException, CriApiException {
        // Arrange
        var credentialIssuerConfig = getMockCredentialIssuerConfig(mockServer);

        when(mockConfigService.getSsmParameter(ConfigurationVariable.JWT_TTL_SECONDS))
                .thenReturn("900");
        when(mockConfigService.getOauthCriConfig(any())).thenReturn(credentialIssuerConfig);
        when(mockConfigService.getCriPrivateApiKey(any())).thenReturn(PRIVATE_API_KEY);

        // Fix the signature here as mocking out the AWSKMS class inside the real signer would be
        // painful.
        when(mockSigner.sign(any(), any())).thenReturn(new Base64URL(CLIENT_ASSERTION_SIGNATURE));
        when(mockSigner.supportedJWSAlgorithms()).thenReturn(Set.of(JWSAlgorithm.ES256));
        when(mockSecureTokenHelper.generate())
                .thenReturn("ScnF4dGXthZYXS_5k85ObEoSU04W-H3qa_p6npv2ZUY");

        // We need to generate a fixed request, so we set the secure token and expiry to constant
        // values.
        var underTest =
                new CriApiService(
                        mockConfigService, mockSigner, mockSecureTokenHelper, CURRENT_TIME);

        // Act
        CriApiException exception =
                assertThrows(
                        CriApiException.class,
                        () ->
                                underTest.fetchAccessToken(
                                        getCallbackRequest(
                                                "dummyInvalidAuthCode", credentialIssuerConfig),
                                        getCriOAuthSessionItem()));

        // Assert
        assertThat(exception.getErrorResponse(), is(ErrorResponse.INVALID_TOKEN_REQUEST));
        assertThat(exception.getHttpStatusCode(), is(HTTPResponse.SC_BAD_REQUEST));
    }

    @Pact(provider = "DcmawCriProvider", consumer = "IpvCoreBack")
    public RequestResponsePact validRequestReturnsDvlaCredential(PactDslWithProvider builder) {
        return builder.given("dummyApiKey is a valid api key")
                .given("dummyAccessToken is a valid access token")
                .given("test-subject is a valid subject")
                .given("dummyDcmawComponentId is a valid issuer")
                .given("the current time is 2099-01-01 00:00:00")
                .given("VC is from DCMAW-410-AC1")
                .uponReceiving("Valid credential request for DVLA VC")
                .path("/credential")
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
    @PactTestFor(pactMethod = "validRequestReturnsDvlaCredential")
    void fetchVerifiableCredential_whenCalledAgainstDcmawCri_retrievesAValidDvlaVc(
            MockServer mockServer) throws URISyntaxException, CriApiException {
        // Arrange
        var credentialIssuerConfig = getMockCredentialIssuerConfig(mockServer);
        configureMockConfigService(credentialIssuerConfig);

        // We need to generate a fixed request, so we set the secure token and expiry to constant
        // values.
        var underTest =
                new CriApiService(
                        mockConfigService, mockSigner, mockSecureTokenHelper, CURRENT_TIME);

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

                                JsonNode addressNode = credentialSubject.get("address").get(0);
                                JsonNode nameParts =
                                        credentialSubject.get("name").get(0).get("nameParts");
                                JsonNode birthDateNode = credentialSubject.get("birthDate").get(0);
                                JsonNode drivingPermitNode =
                                        credentialSubject.get("drivingPermit").get(0);

                                assertEquals("CH1 1AQ", addressNode.get("postalCode").asText());

                                assertEquals("GivenName", nameParts.get(0).get("type").asText());
                                assertEquals("GivenName", nameParts.get(1).get("type").asText());
                                assertEquals("FamilyName", nameParts.get(2).get("type").asText());
                                assertEquals("Joe", nameParts.get(0).get("value").asText());
                                assertEquals("Shmoe", nameParts.get(1).get("value").asText());
                                assertEquals(
                                        "Doe The Ball", nameParts.get(2).get("value").asText());

                                assertEquals(
                                        "2023-01-18", drivingPermitNode.get("expiryDate").asText());
                                assertEquals(
                                        "DOE99802085J99FG",
                                        drivingPermitNode.get("personalNumber").asText());
                                assertEquals("DVLA", drivingPermitNode.get("issuedBy").asText());

                                assertEquals("1985-02-08", birthDateNode.get("value").asText());

                                assertEquals(3, evidence.get("strengthScore").asInt());
                                assertEquals(2, evidence.get("validityScore").asInt());
                                assertEquals(1, evidence.get("activityHistoryScore").asInt());
                            } catch (VerifiableCredentialException
                                    | ParseException
                                    | JsonProcessingException e) {
                                throw new RuntimeException(e);
                            }
                        });
    }

    @Pact(provider = "DcmawCriProvider", consumer = "IpvCoreBack")
    public RequestResponsePact validRequestReturnsDvlaCredentialWithNoGivenName(
            PactDslWithProvider builder) {
        return builder.given("dummyApiKey is a valid api key")
                .given("dummyAccessToken is a valid access token")
                .given("test-subject is a valid subject")
                .given("dummyDcmawComponentId is a valid issuer")
                .given("the current time is 2099-01-01 00:00:00")
                .given("VC is from DCMAW-410-AC1 with given names removed")
                .uponReceiving("Valid credential request for DVLA VC")
                .path("/credential")
                .method("POST")
                .headers("x-api-key", PRIVATE_API_KEY, "Authorization", "Bearer dummyAccessToken")
                .willRespondWith()
                .status(200)
                .body(
                        new PactJwtIgnoreSignatureBodyBuilder(
                                VALID_VC_HEADER,
                                VALID_DVLA_VC_NO_GIVEN_NAME_BODY,
                                VALID_DVLA_VC_NO_GIVEN_NAME_SIGNATURE))
                .toPact();
    }

    @Test
    @PactTestFor(pactMethod = "validRequestReturnsDvlaCredentialWithNoGivenName")
    void fetchVerifiableCredential_whenCalledAgainstDcmawCri_retrievesAValidDvlaVcWithNoGivenName(
            MockServer mockServer) throws URISyntaxException, CriApiException {
        // Arrange
        var credentialIssuerConfig = getMockCredentialIssuerConfig(mockServer);
        configureMockConfigService(credentialIssuerConfig);

        // We need to generate a fixed request, so we set the secure token and expiry to constant
        // values.
        var underTest =
                new CriApiService(
                        mockConfigService, mockSigner, mockSecureTokenHelper, CURRENT_TIME);

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

                                JsonNode addressNode = credentialSubject.get("address").get(0);
                                JsonNode nameParts =
                                        credentialSubject.get("name").get(0).get("nameParts");
                                JsonNode birthDateNode = credentialSubject.get("birthDate").get(0);
                                JsonNode drivingPermitNode =
                                        credentialSubject.get("drivingPermit").get(0);

                                assertEquals("CH1 1AQ", addressNode.get("postalCode").asText());

                                assertEquals(1, nameParts.size());
                                assertEquals("FamilyName", nameParts.get(0).get("type").asText());
                                assertEquals(
                                        "Doe The Ball", nameParts.get(0).get("value").asText());

                                assertEquals(
                                        "2023-01-18", drivingPermitNode.get("expiryDate").asText());
                                assertEquals(
                                        "DOE99802085J99FG",
                                        drivingPermitNode.get("personalNumber").asText());
                                assertEquals("DVLA", drivingPermitNode.get("issuedBy").asText());

                                assertEquals("1985-02-08", birthDateNode.get("value").asText());

                                assertEquals(3, evidence.get("strengthScore").asInt());
                                assertEquals(2, evidence.get("validityScore").asInt());
                                assertEquals(1, evidence.get("activityHistoryScore").asInt());
                            } catch (VerifiableCredentialException
                                    | ParseException
                                    | JsonProcessingException e) {
                                throw new RuntimeException(e);
                            }
                        });
    }

    @Pact(provider = "DcmawCriProvider", consumer = "IpvCoreBack")
    public RequestResponsePact validRequestReturnsDvlaResponseFailedWithCi(
            PactDslWithProvider builder) {
        return builder.given("dummyApiKey is a valid api key")
                .given("dummyAccessToken is a valid access token")
                .given("test-subject is a valid subject")
                .given("dummyDcmawComponentId is a valid issuer")
                .given("the current time is 2099-01-01 00:00:00")
                .given("VC is from DCMAW-5477-AC1")
                .uponReceiving("Valid credential request for DVLA VC with CI")
                .path("/credential")
                .method("POST")
                .headers("x-api-key", PRIVATE_API_KEY, "Authorization", "Bearer dummyAccessToken")
                .willRespondWith()
                .status(200)
                .body(
                        new PactJwtIgnoreSignatureBodyBuilder(
                                VALID_VC_HEADER,
                                FAILED_DVLA_VC_WITH_CI_BODY,
                                FAILED_DVLA_VC_WITH_CI_SIGNATURE))
                .toPact();
    }

    @Test
    @PactTestFor(pactMethod = "validRequestReturnsDvlaResponseFailedWithCi")
    void fetchVerifiableCredential_whenCalledAgainstDcmawCri_retrievesAFailedDvlaVcWithACi(
            MockServer mockServer) throws URISyntaxException, CriApiException {
        // Arrange
        var credentialIssuerConfig = getMockCredentialIssuerConfig(mockServer);
        configureMockConfigService(credentialIssuerConfig);

        // We need to generate a fixed request, so we set the secure token and expiry to constant
        // values.
        var underTest =
                new CriApiService(
                        mockConfigService, mockSigner, mockSecureTokenHelper, CURRENT_TIME);

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

                                assertEquals("V01", ciNode.get(0).asText());

                                assertEquals("CH62 6AQ", addressNode.get("postalCode").asText());

                                assertEquals("GivenName", nameParts.get(0).get("type").asText());
                                assertEquals("FamilyName", nameParts.get(1).get("type").asText());
                                assertEquals("Jane", nameParts.get(0).get("value").asText());
                                assertEquals("Doe", nameParts.get(1).get("value").asText());

                                assertEquals(
                                        "2028-08-07", drivingPermitNode.get("expiryDate").asText());
                                assertEquals(
                                        "DOEDO861281JF9DH",
                                        drivingPermitNode.get("personalNumber").asText());
                                assertEquals("DVLA", drivingPermitNode.get("issuedBy").asText());

                                assertEquals("1981-11-28", birthDateNode.get("value").asText());

                                assertEquals(3, evidence.get("strengthScore").asInt());
                                assertEquals(0, evidence.get("validityScore").asInt());
                                assertEquals(0, evidence.get("activityHistoryScore").asInt());
                            } catch (VerifiableCredentialException
                                    | ParseException
                                    | JsonProcessingException e) {
                                throw new RuntimeException(e);
                            }
                        });
    }

    @Pact(provider = "DcmawCriProvider", consumer = "IpvCoreBack")
    public RequestResponsePact validRequestReturnsDvaResponseFailedNoCis(
            PactDslWithProvider builder) {
        return builder.given("dummyApiKey is a valid api key")
                .given("dummyAccessToken is a valid access token")
                .given("test-subject is a valid subject")
                .given("dummyDcmawComponentId is a valid issuer")
                .given("the current time is 2099-01-01 00:00:00")
                .given("VC is from DCMAW-1045-AC1")
                .uponReceiving("Valid credential request for DVA failed VC with no CIs")
                .path("/credential")
                .method("POST")
                .headers("x-api-key", PRIVATE_API_KEY, "Authorization", "Bearer dummyAccessToken")
                .willRespondWith()
                .status(200)
                .body(
                        new PactJwtIgnoreSignatureBodyBuilder(
                                VALID_VC_HEADER,
                                FAILED_DVA_VC_NO_CI_BODY,
                                FAILED_DVA_VC_NO_CI_SIGNATURE))
                .toPact();
    }

    @Test
    @PactTestFor(pactMethod = "validRequestReturnsDvaResponseFailedNoCis")
    void fetchVerifiableCredential_whenCalledAgainstDcmawCri_retrievesAFailedDvaVcWithNoCis(
            MockServer mockServer) throws URISyntaxException, CriApiException {
        // Arrange
        var credentialIssuerConfig = getMockCredentialIssuerConfig(mockServer);
        configureMockConfigService(credentialIssuerConfig);

        // We need to generate a fixed request, so we set the secure token and expiry to constant
        // values.
        var underTest =
                new CriApiService(
                        mockConfigService, mockSigner, mockSecureTokenHelper, CURRENT_TIME);

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

                                ArrayNode ciNode = (ArrayNode) evidence.get("ci");
                                JsonNode addressNode = credentialSubject.get("address").get(0);
                                JsonNode nameParts =
                                        credentialSubject.get("name").get(0).get("nameParts");
                                JsonNode birthDateNode = credentialSubject.get("birthDate").get(0);
                                JsonNode drivingPermitNode =
                                        credentialSubject.get("drivingPermit").get(0);

                                assertEquals(0, ciNode.size());

                                assertEquals("EH1 9GP", addressNode.get("postalCode").asText());

                                assertEquals("GivenName", nameParts.get(0).get("type").asText());
                                assertEquals("GivenName", nameParts.get(1).get("type").asText());
                                assertEquals("FamilyName", nameParts.get(2).get("type").asText());
                                assertEquals("SARAH", nameParts.get(0).get("value").asText());
                                assertEquals("MEREDYTH", nameParts.get(1).get("value").asText());
                                assertEquals("MORGAN", nameParts.get(2).get("value").asText());

                                assertEquals(
                                        "2023-01-18", drivingPermitNode.get("expiryDate").asText());
                                assertEquals(
                                        "MORGA753116SM9IJ",
                                        drivingPermitNode.get("personalNumber").asText());
                                assertEquals("DVA", drivingPermitNode.get("issuedBy").asText());

                                assertEquals("1976-03-11", birthDateNode.get("value").asText());

                                assertEquals(3, evidence.get("strengthScore").asInt());
                                assertEquals(0, evidence.get("validityScore").asInt());
                                assertEquals(0, evidence.get("activityHistoryScore").asInt());
                            } catch (VerifiableCredentialException
                                    | ParseException
                                    | JsonProcessingException e) {
                                throw new RuntimeException(e);
                            }
                        });
    }

    @Pact(provider = "DcmawCriProvider", consumer = "IpvCoreBack")
    public RequestResponsePact validRequestReturnsDvaCredential(PactDslWithProvider builder) {
        return builder.given("dummyApiKey is a valid api key")
                .given("dummyAccessToken is a valid access token")
                .given("test-subject is a valid subject")
                .given("dummyDcmawComponentId is a valid issuer")
                .given("the current time is 2099-01-01 00:00:00")
                .given("VC is from DCMAW-1559-AC2")
                .uponReceiving("Valid credential request for DVA VC")
                .path("/credential")
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
    @PactTestFor(pactMethod = "validRequestReturnsDvaCredential")
    void fetchVerifiableCredential_whenCalledAgainstDcmawCri_retrievesAValidDvaVc(
            MockServer mockServer) throws URISyntaxException, CriApiException {
        // Arrange
        var credentialIssuerConfig = getMockCredentialIssuerConfig(mockServer);
        configureMockConfigService(credentialIssuerConfig);

        // We need to generate a fixed request, so we set the secure token and expiry to constant
        // values.
        var underTest =
                new CriApiService(
                        mockConfigService, mockSigner, mockSecureTokenHelper, CURRENT_TIME);

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

                                JsonNode addressNode = credentialSubject.get("address").get(0);
                                JsonNode nameParts =
                                        credentialSubject.get("name").get(0).get("nameParts");
                                JsonNode birthDateNode = credentialSubject.get("birthDate").get(0);
                                JsonNode drivingPermitNode =
                                        credentialSubject.get("drivingPermit").get(0);

                                assertEquals(
                                        JsonNodeType.NULL,
                                        addressNode.get("postalCode").getNodeType());

                                assertEquals("GivenName", nameParts.get(0).get("type").asText());
                                assertEquals("GivenName", nameParts.get(1).get("type").asText());
                                assertEquals("FamilyName", nameParts.get(2).get("type").asText());
                                assertEquals("OLGA", nameParts.get(0).get("value").asText());
                                assertEquals("A", nameParts.get(1).get("value").asText());
                                assertEquals("KULYK", nameParts.get(2).get("value").asText());

                                assertEquals(
                                        "2028-02-20", drivingPermitNode.get("expiryDate").asText());
                                assertEquals(
                                        "2022-05-29", drivingPermitNode.get("issueDate").asText());
                                assertEquals(
                                        "5823131861",
                                        drivingPermitNode.get("personalNumber").asText());
                                assertEquals("DVA", drivingPermitNode.get("issuedBy").asText());

                                assertEquals("1980-09-27", birthDateNode.get("value").asText());

                                assertEquals(3, evidence.get("strengthScore").asInt());
                                assertEquals(2, evidence.get("validityScore").asInt());
                                assertEquals(1, evidence.get("activityHistoryScore").asInt());
                            } catch (VerifiableCredentialException
                                    | ParseException
                                    | JsonProcessingException e) {
                                throw new RuntimeException(e);
                            }
                        });
    }

    @Pact(provider = "DcmawCriProvider", consumer = "IpvCoreBack")
    public RequestResponsePact validRequestReturnsDrivingLicenceCredential(
            PactDslWithProvider builder) {
        return builder.given("dummyApiKey is a valid api key")
                .given("dummyAccessToken is a valid access token")
                .given("test-subject is a valid subject")
                .given("dummyDcmawComponentId is a valid issuer")
                .given("the current time is 2099-01-01 00:00:00")
                .given("VC is from DCMAW-4733-AC1")
                .uponReceiving("Valid credential request for DVA VC")
                .path("/credential")
                .method("POST")
                .headers("x-api-key", PRIVATE_API_KEY, "Authorization", "Bearer dummyAccessToken")
                .willRespondWith()
                .status(200)
                .body(
                        new PactJwtIgnoreSignatureBodyBuilder(
                                VALID_VC_HEADER,
                                VALID_DRIVING_LICENCE_NO_ISSUER_VC_BODY,
                                VALID_DRIVING_LICENCE_NO_ISSUER_VC_SIGNATURE))
                .toPact();
    }

    @Test
    @PactTestFor(pactMethod = "validRequestReturnsDrivingLicenceCredential")
    void fetchVerifiableCredential_whenCalledAgainstDcmawCri_retrievesAValidDvaVcWithNoIssuer(
            MockServer mockServer) throws URISyntaxException, CriApiException {
        // Arrange
        var credentialIssuerConfig = getMockCredentialIssuerConfig(mockServer);
        configureMockConfigService(credentialIssuerConfig);

        // We need to generate a fixed request, so we set the secure token and expiry to constant
        // values.
        var underTest =
                new CriApiService(
                        mockConfigService, mockSigner, mockSecureTokenHelper, CURRENT_TIME);

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

                                JsonNode addressNode = credentialSubject.get("address").get(0);
                                JsonNode nameParts =
                                        credentialSubject.get("name").get(0).get("nameParts");
                                JsonNode birthDateNode = credentialSubject.get("birthDate").get(0);
                                JsonNode drivingPermitNode =
                                        credentialSubject.get("drivingPermit").get(0);

                                assertEquals("CH62 2AQ", addressNode.get("postalCode").asText());

                                assertEquals("GivenName", nameParts.get(0).get("type").asText());
                                assertEquals("GivenName", nameParts.get(1).get("type").asText());
                                assertEquals("FamilyName", nameParts.get(2).get("type").asText());
                                assertEquals("Jane", nameParts.get(0).get("value").asText());
                                assertEquals("Julian", nameParts.get(1).get("value").asText());
                                assertEquals("Boe", nameParts.get(2).get("value").asText());

                                assertEquals(
                                        "2028-08-07", drivingPermitNode.get("expiryDate").asText());
                                assertEquals(
                                        "BOEJJ861281TP9DH",
                                        drivingPermitNode.get("personalNumber").asText());
                                assertEquals(
                                        JsonNodeType.NULL,
                                        drivingPermitNode.get("issuedBy").getNodeType());

                                assertEquals("2011-11-28", birthDateNode.get("value").asText());

                                assertEquals(3, evidence.get("strengthScore").asInt());
                                assertEquals(2, evidence.get("validityScore").asInt());
                                assertEquals(1, evidence.get("activityHistoryScore").asInt());
                            } catch (VerifiableCredentialException
                                    | ParseException
                                    | JsonProcessingException e) {
                                throw new RuntimeException(e);
                            }
                        });
    }

    @Pact(provider = "DcmawCriProvider", consumer = "IpvCoreBack")
    public RequestResponsePact validRequestReturnsPassportCredential(PactDslWithProvider builder) {
        return builder.given("dummyApiKey is a valid api key")
                .given("dummyAccessToken is a valid access token")
                .given("test-subject is a valid subject")
                .given("dummyDcmawComponentId is a valid issuer")
                .given("the current time is 2099-01-01 00:00:00")
                .given("VC is from DCMAW-3079-AC1")
                .uponReceiving("Valid credential request for passport VC")
                .path("/credential")
                .method("POST")
                .headers("x-api-key", PRIVATE_API_KEY, "Authorization", "Bearer dummyAccessToken")
                .willRespondWith()
                .status(200)
                .body(
                        new PactJwtIgnoreSignatureBodyBuilder(
                                VALID_VC_HEADER,
                                VALID_UK_PASSPORT_VC_BODY,
                                VALID_UK_PASSPORT_VC_SIGNATURE))
                .toPact();
    }

    @Test
    @PactTestFor(pactMethod = "validRequestReturnsPassportCredential")
    void fetchVerifiableCredential_whenCalledAgainstDcmawCri_retrievesAValidPassportVc(
            MockServer mockServer) throws URISyntaxException, CriApiException {
        // Arrange
        var credentialIssuerConfig = getMockCredentialIssuerConfig(mockServer);
        configureMockConfigService(credentialIssuerConfig);

        // We need to generate a fixed request, so we set the secure token and expiry to constant
        // values.
        var underTest =
                new CriApiService(
                        mockConfigService, mockSigner, mockSecureTokenHelper, CURRENT_TIME);

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

                                JsonNode nameParts =
                                        credentialSubject.get("name").get(0).get("nameParts");
                                JsonNode birthDateNode = credentialSubject.get("birthDate").get(0);
                                JsonNode passport = credentialSubject.get("passport").get(0);

                                assertEquals("GivenName", nameParts.get(0).get("type").asText());
                                assertEquals("GivenName", nameParts.get(1).get("type").asText());
                                assertEquals("FamilyName", nameParts.get(2).get("type").asText());
                                assertEquals("ANNA", nameParts.get(0).get("value").asText());
                                assertEquals("NICHOLA", nameParts.get(1).get("value").asText());
                                assertEquals(
                                        "OTHER FORTYFOUR", nameParts.get(2).get("value").asText());

                                assertEquals("2027-08-01", passport.get("expiryDate").asText());
                                assertEquals("549364783", passport.get("documentNumber").asText());
                                assertEquals("GBR", passport.get("icaoIssuerCode").asText());
                                assertNull(passport.get("documentType"));

                                assertEquals("1960-01-01", birthDateNode.get("value").asText());

                                assertEquals(4, evidence.get("strengthScore").asInt());
                                assertEquals(3, evidence.get("validityScore").asInt());
                            } catch (VerifiableCredentialException
                                    | ParseException
                                    | JsonProcessingException e) {
                                throw new RuntimeException(e);
                            }
                        });
    }

    @Pact(provider = "DcmawCriProvider", consumer = "IpvCoreBack")
    public RequestResponsePact validRequestReturnsNldPassportCredential(
            PactDslWithProvider builder) {
        return builder.given("dummyApiKey is a valid api key")
                .given("dummyAccessToken is a valid access token") // qqqqqqqqqqq
                .given("test-subject is a valid subject")
                .given("dummyDcmawComponentId is a valid issuer")
                .given("the current time is 2099-01-01 00:00:00")
                .given("Returned VC is from DCMAW-5176-AC1")
                .uponReceiving("Valid credential request for passport VC")
                .path("/credential")
                .method("POST")
                .headers("x-api-key", PRIVATE_API_KEY, "Authorization", "Bearer dummyAccessToken")
                .willRespondWith()
                .status(200)
                .body(
                        new PactJwtIgnoreSignatureBodyBuilder(
                                VALID_VC_HEADER,
                                VALID_NLD_PASSPORT_VC_BODY,
                                VALID_NLD_PASSPORT_VC_SIGNATURE))
                .toPact();
    }

    @Test
    @PactTestFor(pactMethod = "validRequestReturnsNldPassportCredential")
    void fetchVerifiableCredential_whenCalledAgainstDcmawCri_retrievesAValidNldPassportVc(
            MockServer mockServer) throws URISyntaxException, CriApiException {
        // Arrange
        var credentialIssuerConfig = getMockCredentialIssuerConfig(mockServer);
        configureMockConfigService(credentialIssuerConfig);

        // We need to generate a fixed request, so we set the secure token and expiry to constant
        // values.
        var underTest =
                new CriApiService(
                        mockConfigService, mockSigner, mockSecureTokenHelper, CURRENT_TIME);

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

                                JsonNode nameParts =
                                        credentialSubject.get("name").get(0).get("nameParts");
                                JsonNode birthDateNode = credentialSubject.get("birthDate").get(0);
                                JsonNode passport = credentialSubject.get("passport").get(0);

                                assertEquals("GivenName", nameParts.get(0).get("type").asText());
                                assertEquals("GivenName", nameParts.get(1).get("type").asText());
                                assertEquals("FamilyName", nameParts.get(2).get("type").asText());
                                assertEquals("OLGA", nameParts.get(0).get("value").asText());
                                assertEquals(
                                        "ANATOLIYIVNA", nameParts.get(1).get("value").asText());
                                assertEquals("KULYK", nameParts.get(2).get("value").asText());

                                assertEquals("2026-04-01", passport.get("expiryDate").asText());
                                assertEquals("NXC65LP76", passport.get("documentNumber").asText());
                                assertEquals("NLD", passport.get("icaoIssuerCode").asText());
                                assertNull(passport.get("documentType"));

                                assertEquals("1980-09-27", birthDateNode.get("value").asText());

                                assertEquals(4, evidence.get("strengthScore").asInt());
                                assertEquals(3, evidence.get("validityScore").asInt());
                            } catch (VerifiableCredentialException
                                    | ParseException
                                    | JsonProcessingException e) {
                                throw new RuntimeException(e);
                            }
                        });
    }

    @Pact(provider = "DcmawCriProvider", consumer = "IpvCoreBack")
    public RequestResponsePact validRequestReturnsFailedPassportCredential(
            PactDslWithProvider builder) {
        return builder.given("dummyApiKey is a valid api key")
                .given("dummyAccessToken is a valid access token")
                .given("test-subject is a valid subject")
                .given("dummyDcmawComponentId is a valid issuer")
                .given("the current time is 2099-01-01 00:00:00")
                .given("VC is from DCMAW-3171-AC2")
                .uponReceiving("Valid credential request for failed passport VC")
                .path("/credential")
                .method("POST")
                .headers("x-api-key", PRIVATE_API_KEY, "Authorization", "Bearer dummyAccessToken")
                .willRespondWith()
                .status(200)
                .body(
                        new PactJwtIgnoreSignatureBodyBuilder(
                                VALID_VC_HEADER,
                                FAILED_PASSPORT_VC_WITH_CI_BODY,
                                FAILED_PASSPORT_VC_WITH_CI_SIGNATURE))
                .toPact();
    }

    @Test
    @PactTestFor(pactMethod = "validRequestReturnsFailedPassportCredential")
    void fetchVerifiableCredential_whenCalledAgainstDcmawCri_retrievesAFailedPassportVc(
            MockServer mockServer) throws URISyntaxException, CriApiException {
        // Arrange
        var credentialIssuerConfig = getMockCredentialIssuerConfig(mockServer);
        configureMockConfigService(credentialIssuerConfig);

        // We need to generate a fixed request, so we set the secure token and expiry to constant
        // values.
        var underTest =
                new CriApiService(
                        mockConfigService, mockSigner, mockSecureTokenHelper, CURRENT_TIME);

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

                                JsonNode nameParts =
                                        credentialSubject.get("name").get(0).get("nameParts");
                                JsonNode birthDateNode = credentialSubject.get("birthDate").get(0);
                                JsonNode passport = credentialSubject.get("passport").get(0);

                                assertEquals("V01", ciNode.get(0).asText());

                                assertEquals("GivenName", nameParts.get(0).get("type").asText());
                                assertEquals("GivenName", nameParts.get(1).get("type").asText());
                                assertEquals("FamilyName", nameParts.get(2).get("type").asText());
                                assertEquals("ANNA", nameParts.get(0).get("value").asText());
                                assertEquals("NICHOLA", nameParts.get(1).get("value").asText());
                                assertEquals(
                                        "OTHER FORTYFOUR", nameParts.get(2).get("value").asText());

                                assertEquals("2027-08-01", passport.get("expiryDate").asText());
                                assertEquals("549364783", passport.get("documentNumber").asText());
                                assertEquals("GBR", passport.get("icaoIssuerCode").asText());
                                assertNull(passport.get("documentType"));

                                assertEquals("1960-01-01", birthDateNode.get("value").asText());

                                assertEquals(4, evidence.get("strengthScore").asInt());
                                assertEquals(0, evidence.get("validityScore").asInt());
                            } catch (VerifiableCredentialException
                                    | ParseException
                                    | JsonProcessingException e) {
                                throw new RuntimeException(e);
                            }
                        });
    }

    @Pact(provider = "DcmawCriProvider", consumer = "IpvCoreBack")
    public RequestResponsePact validRequestReturnsBrpCredential(PactDslWithProvider builder) {
        return builder.given("dummyApiKey is a valid api key")
                .given("dummyAccessToken is a valid access token")
                .given("test-subject is a valid subject")
                .given("dummyDcmawComponentId is a valid issuer")
                .given("the current time is 2099-01-01 00:00:00")
                .given("VC is from DCMAW-5176-AC1")
                .uponReceiving("Valid credential request for passport VC")
                .path("/credential")
                .method("POST")
                .headers("x-api-key", PRIVATE_API_KEY, "Authorization", "Bearer dummyAccessToken")
                .willRespondWith()
                .status(200)
                .body(
                        new PactJwtIgnoreSignatureBodyBuilder(
                                VALID_VC_HEADER, VALID_BRP_VC_BODY, VALID_BRP_VC_SIGNATURE))
                .toPact();
    }

    @Test
    @PactTestFor(pactMethod = "validRequestReturnsBrpCredential")
    void fetchVerifiableCredential_whenCalledAgainstDcmawCri_retrievesAValidBrpVc(
            MockServer mockServer) throws URISyntaxException, CriApiException {
        // Arrange
        var credentialIssuerConfig = getMockCredentialIssuerConfig(mockServer);
        configureMockConfigService(credentialIssuerConfig);

        // We need to generate a fixed request, so we set the secure token and expiry to constant
        // values.
        var underTest =
                new CriApiService(
                        mockConfigService, mockSigner, mockSecureTokenHelper, CURRENT_TIME);

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

                                JsonNode nameParts =
                                        credentialSubject.get("name").get(0).get("nameParts");
                                JsonNode birthDateNode = credentialSubject.get("birthDate").get(0);
                                JsonNode brp = credentialSubject.get("residencePermit").get(0);

                                assertEquals("GivenName", nameParts.get(0).get("type").asText());
                                assertEquals("FamilyName", nameParts.get(1).get("type").asText());
                                assertEquals("LATEFAMFOUR", nameParts.get(0).get("value").asText());
                                assertEquals(
                                        "LATEFAMLASTFOUR", nameParts.get(1).get("value").asText());

                                assertEquals("2024-02-25", brp.get("expiryDate").asText());
                                assertEquals("ZR8016200", brp.get("documentNumber").asText());
                                assertEquals("GBR", brp.get("icaoIssuerCode").asText());
                                assertEquals("IR", brp.get("documentType").asText());

                                assertEquals("1980-01-01", birthDateNode.get("value").asText());

                                assertEquals(4, evidence.get("strengthScore").asInt());
                                assertEquals(3, evidence.get("validityScore").asInt());
                            } catch (VerifiableCredentialException
                                    | ParseException
                                    | JsonProcessingException e) {
                                throw new RuntimeException(e);
                            }
                        });
    }

    @Pact(provider = "DcmawCriProvider", consumer = "IpvCoreBack")
    public RequestResponsePact validRequestReturnsFailedBrpCredential(PactDslWithProvider builder) {
        return builder.given("dummyApiKey is a valid api key")
                .given("dummyAccessToken is a valid access token")
                .given("test-subject is a valid subject")
                .given("dummyDcmawComponentId is a valid issuer")
                .given("the current time is 2099-01-01 00:00:00")
                .given("VC is from DCMAW-5175-AC1")
                .uponReceiving("Valid credential request for failed BRP VC")
                .path("/credential")
                .method("POST")
                .headers("x-api-key", PRIVATE_API_KEY, "Authorization", "Bearer dummyAccessToken")
                .willRespondWith()
                .status(200)
                .body(
                        new PactJwtIgnoreSignatureBodyBuilder(
                                VALID_VC_HEADER, FAILED_BRP_VC_BODY, FAILED_BRP_VC_SIGNATURE))
                .toPact();
    }

    @Test
    @PactTestFor(pactMethod = "validRequestReturnsFailedBrpCredential")
    void fetchVerifiableCredential_whenCalledAgainstDcmawCri_retrievesAFailedBrpVc(
            MockServer mockServer) throws URISyntaxException, CriApiException {
        // Arrange
        var credentialIssuerConfig = getMockCredentialIssuerConfig(mockServer);
        configureMockConfigService(credentialIssuerConfig);

        // We need to generate a fixed request, so we set the secure token and expiry to constant
        // values.
        var underTest =
                new CriApiService(
                        mockConfigService, mockSigner, mockSecureTokenHelper, CURRENT_TIME);

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

                                JsonNode nameParts =
                                        credentialSubject.get("name").get(0).get("nameParts");
                                JsonNode birthDateNode = credentialSubject.get("birthDate").get(0);
                                JsonNode brp = credentialSubject.get("residencePermit").get(0);

                                assertEquals("V01", ciNode.get(0).asText());

                                assertEquals("GivenName", nameParts.get(0).get("type").asText());
                                assertEquals("FamilyName", nameParts.get(1).get("type").asText());
                                assertEquals("LATEFAMFOUR", nameParts.get(0).get("value").asText());
                                assertEquals(
                                        "LATEFAMLASTFOUR", nameParts.get(1).get("value").asText());

                                assertEquals("2024-02-25", brp.get("expiryDate").asText());
                                assertEquals("ZR8016200", brp.get("documentNumber").asText());
                                assertEquals("GBR", brp.get("icaoIssuerCode").asText());
                                assertEquals("IR", brp.get("documentType").asText());

                                assertEquals("1980-01-01", birthDateNode.get("value").asText());

                                assertEquals(4, evidence.get("strengthScore").asInt());
                                assertEquals(0, evidence.get("validityScore").asInt());
                            } catch (VerifiableCredentialException
                                    | ParseException
                                    | JsonProcessingException e) {
                                throw new RuntimeException(e);
                            }
                        });
    }

    @Pact(provider = "DcmawCriProvider", consumer = "IpvCoreBack")
    public RequestResponsePact validRequestReturnsValidBrcResponse(PactDslWithProvider builder) {
        return builder.given("dummyApiKey is a valid api key")
                .given("dummyAccessToken is a valid access token")
                .given("test-subject is a valid subject")
                .given("dummyDcmawComponentId is a valid issuer")
                .given("the current time is 2099-01-01 00:00:00")
                .given("Returned VC is from DCMAW-5176-AC1")
                .uponReceiving("Valid credential request for valid BRC VC")
                .path("/credential")
                .method("POST")
                .headers("x-api-key", PRIVATE_API_KEY, "Authorization", "Bearer dummyAccessToken")
                .willRespondWith()
                .status(200)
                .body(
                        new PactJwtIgnoreSignatureBodyBuilder(
                                VALID_VC_HEADER, VALID_BRC_VC_BODY, VALID_BRC_VC_SIGNATURE))
                .toPact();
    }

    @Test
    @PactTestFor(pactMethod = "validRequestReturnsValidBrcResponse")
    void fetchVerifiableCredential_whenCalledAgainstDcmawCri_retrievesAValidBrc(
            MockServer mockServer) throws URISyntaxException, CriApiException {
        // Arrange
        var credentialIssuerConfig = getMockCredentialIssuerConfig(mockServer);
        configureMockConfigService(credentialIssuerConfig);

        // We need to generate a fixed request, so we set the secure token and expiry to constant
        // values.
        var underTest =
                new CriApiService(
                        mockConfigService, mockSigner, mockSecureTokenHelper, CURRENT_TIME);

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

                                JsonNode nameParts =
                                        credentialSubject.get("name").get(0).get("nameParts");
                                JsonNode birthDateNode = credentialSubject.get("birthDate").get(0);
                                JsonNode residencePermitNode =
                                        credentialSubject.get("residencePermit").get(0);

                                assertEquals("GivenName", nameParts.get(0).get("type").asText());
                                assertEquals("FamilyName", nameParts.get(1).get("type").asText());
                                assertEquals("LATEFAMFOUR", nameParts.get(0).get("value").asText());
                                assertEquals(
                                        "LATEFAMLASTFOUR", nameParts.get(1).get("value").asText());

                                assertEquals(
                                        "2024-02-25",
                                        residencePermitNode.get("expiryDate").asText());
                                assertEquals(
                                        "ZR8016200",
                                        residencePermitNode.get("documentNumber").asText());
                                assertEquals(
                                        "GBR", residencePermitNode.get("icaoIssuerCode").asText());
                                assertEquals(
                                        "CR", residencePermitNode.get("documentType").asText());

                                assertEquals("1980-01-01", birthDateNode.get("value").asText());

                                assertEquals(4, evidence.get("strengthScore").asInt());
                                assertEquals(3, evidence.get("validityScore").asInt());
                            } catch (VerifiableCredentialException
                                    | ParseException
                                    | JsonProcessingException e) {
                                throw new RuntimeException(e);
                            }
                        });
    }

    @Pact(provider = "DcmawCriProvider", consumer = "IpvCoreBack")
    public RequestResponsePact validRequestReturnsFailedBrcResponse(PactDslWithProvider builder) {
        return builder.given("dummyApiKey is a valid api key")
                .given("dummyAccessToken is a valid access token")
                .given("test-subject is a valid subject")
                .given("dummyDcmawComponentId is a valid issuer")
                .given("the current time is 2099-01-01 00:00:00")
                .given("Returned VC is from DCMAW-5175-AC2")
                .uponReceiving("Valid credential request for failed BRC VC")
                .path("/credential")
                .method("POST")
                .headers("x-api-key", PRIVATE_API_KEY, "Authorization", "Bearer dummyAccessToken")
                .willRespondWith()
                .status(200)
                .body(
                        new PactJwtIgnoreSignatureBodyBuilder(
                                VALID_VC_HEADER, FAILED_BRC_VC_BODY, FAILED_BRC_VC_SIGNATURE))
                .toPact();
    }

    @Test
    @PactTestFor(pactMethod = "validRequestReturnsFailedBrcResponse")
    void fetchVerifiableCredential_whenCalledAgainstDcmawCri_retrievesAFailedBrc(
            MockServer mockServer) throws URISyntaxException, CriApiException {
        // Arrange
        var credentialIssuerConfig = getMockCredentialIssuerConfig(mockServer);
        configureMockConfigService(credentialIssuerConfig);

        // We need to generate a fixed request, so we set the secure token and expiry to constant
        // values.
        var underTest =
                new CriApiService(
                        mockConfigService, mockSigner, mockSecureTokenHelper, CURRENT_TIME);

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

                                ArrayNode ciNode = (ArrayNode) evidence.get("ci");
                                JsonNode nameParts =
                                        credentialSubject.get("name").get(0).get("nameParts");
                                JsonNode birthDateNode = credentialSubject.get("birthDate").get(0);
                                JsonNode residencePermitNode =
                                        credentialSubject.get("residencePermit").get(0);

                                assertEquals(0, ciNode.size());

                                assertEquals("GivenName", nameParts.get(0).get("type").asText());
                                assertEquals("FamilyName", nameParts.get(1).get("type").asText());
                                assertEquals("LATEFAMFOUR", nameParts.get(0).get("value").asText());
                                assertEquals(
                                        "LATEFAMLASTFOUR", nameParts.get(1).get("value").asText());

                                assertEquals(
                                        "2024-02-25",
                                        residencePermitNode.get("expiryDate").asText());
                                assertEquals(
                                        "ZR8016200",
                                        residencePermitNode.get("documentNumber").asText());
                                assertEquals(
                                        "GBR", residencePermitNode.get("icaoIssuerCode").asText());
                                assertEquals(
                                        "CR", residencePermitNode.get("documentType").asText());

                                assertEquals("1980-01-01", birthDateNode.get("value").asText());

                                assertEquals(4, evidence.get("strengthScore").asInt());
                                assertEquals(0, evidence.get("validityScore").asInt());
                            } catch (VerifiableCredentialException
                                    | ParseException
                                    | JsonProcessingException e) {
                                throw new RuntimeException(e);
                            }
                        });
    }

    @Pact(provider = "DcmawCriProvider", consumer = "IpvCoreBack")
    public RequestResponsePact invalidAccessTokenReturns403(PactDslWithProvider builder) {
        return builder.given("dummyApiKey is a valid api key")
                .given("dummyInvalidAccessToken is an invalid access token")
                .given("test-subject is a valid subject")
                .given("dummyDcmawComponentId is a valid issuer")
                .uponReceiving("Invalid credential request due to invalid access token")
                .path("/credential")
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
    void fetchVerifiableCredential_whenCalledAgainstDcmawCriWithInvalidAuthCode_throwsAnException(
            MockServer mockServer) throws URISyntaxException, CriApiException {
        // Arrange
        var credentialIssuerConfig = getMockCredentialIssuerConfig(mockServer);
        configureMockConfigService(credentialIssuerConfig);

        // We need to generate a fixed request, so we set the secure token and expiry to constant
        // values.
        var underTest =
                new CriApiService(
                        mockConfigService, mockSigner, mockSecureTokenHelper, CURRENT_TIME);

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
                "https://identity.staging.account.gov.uk/credential-issuer/callback?id=dcmaw",
                "dummyState",
                null,
                null,
                "dummyIpAddress",
                "dummyFeatureSet");
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
        ciConfigMap.put("V01", ciConfig1);

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
                .credentialUrl(new URI("http://localhost:" + mockServer.getPort() + "/credential"))
                .authorizeUrl(new URI("http://localhost:" + mockServer.getPort() + "/authorize"))
                .clientId(IPV_CORE_CLIENT_ID)
                .signingKey(CRI_SIGNING_PRIVATE_KEY_JWK)
                .encryptionKey(CRI_RSA_ENCRYPTION_PUBLIC_JWK)
                .componentId(TEST_ISSUER)
                .clientCallbackUrl(
                        URI.create(
                                "https://identity.staging.account.gov.uk/credential-issuer/callback?id=dcmaw"))
                .requiresApiKey(true)
                .requiresAdditionalEvidence(false)
                .build();
    }
}
