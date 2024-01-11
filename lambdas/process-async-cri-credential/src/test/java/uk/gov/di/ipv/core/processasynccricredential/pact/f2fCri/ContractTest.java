package uk.gov.di.ipv.core.processasynccricredential.pact.f2fCri;

import au.com.dius.pact.consumer.MessagePactBuilder;
import au.com.dius.pact.consumer.MockServer;
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
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jwt.SignedJWT;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.dto.CredentialIssuerConfig;
import uk.gov.di.ipv.core.library.helpers.FixedTimeJWTClaimsVerifier;
import uk.gov.di.ipv.core.library.helpers.SecureTokenHelper;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.verifiablecredential.validator.VerifiableCredentialJwtValidator;
import uk.gov.di.ipv.core.processasynccricredential.domain.SuccessAsyncCriResponse;
import uk.gov.di.ipv.core.processasynccricredential.dto.CriResponseMessageDto;
import uk.gov.di.ipv.core.processasynccricredential.helpers.JwtParser;
import uk.gov.di.ipv.core.processasynccricredential.pact.JwtBuilder;

import java.net.URI;
import java.net.URISyntaxException;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Date;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static uk.gov.di.ipv.core.processasynccricredential.helpers.AsyncCriResponseHelper.getAsyncResponseMessage;

// @Disabled("PACT tests should not be run in build pipelines at this time")
@ExtendWith(PactConsumerTestExt.class)
@ExtendWith(MockitoExtension.class)
@PactTestFor(providerName = "PassportCriProvider")
@MockServerConfig(hostInterface = "localhost", port = "1234")
public class ContractTest {
    private final JwtParser jwtParser = new JwtParser();
    private final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final String TEST_USER = "test-subject";
    private static final String TEST_OAUTH_STATE = "f5f0d4d1-b937-4abe-b379-8269f600ad44";
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
                              "issueDate": "2005-02-02"
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
    private static final String VALID_F2F_VC_DL_SIGNATURE =
            "X5Zh-XeLVwu6RTeRWuqWW-_wNCEct2UMCrcyDbM5XBgYO02gGZGGW0zg03GTLtJCDNfK7EfduLgQo5MyjHX_TA";
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
    @Mock private JWSSigner mockSigner;
    @Mock private SecureTokenHelper mockSecureTokenHelper;

    @Pact(provider = "F2FCriProvider", consumer = "IpvCoreBack")
    public MessagePact validF2fMessageReturnsIssuedPassportCredential(MessagePactBuilder builder)
            throws JsonProcessingException {
        return builder.given("test-subject is a valid subject")
                .given("dummyF2fComponentId is a valid issuer")
                .given("dummyF2fComponentId is a valid audience")
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
                        createSuccessTestEvent(
                                VALID_F2F_VC_WITH_PASSPORT_BODY, VALID_F2F_VC_PASSPORT_SIGNATURE))
                .toPact();
    }

    @Pact(provider = "F2FCriProvider", consumer = "IpvCoreBack")
    public MessagePact validF2fMessageReturnsIssuedDrivingLicenseCredential(
            MessagePactBuilder builder) throws Exception {
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
                .given("VC evidence validityScore is 2")
                .given("VC evidence verificationScore is 3")
                .given("VC evidence strengthScore is 4")
                .given("VC evidence type is IdentityCheck")
                .given("VC evidence txn is eda339dd-aa83-495c-a4d4-75021e9415f9")
                .given("VC jti is test-jti")
                .expectsToReceive("A valid F2F CRI with Driving License")
                .withContent(
                        createSuccessTestEvent(
                                VALID_F2F_VC_WITH_DVLA_BODY, VALID_F2F_VC_DL_SIGNATURE))
                .toPact();
    }

    @Pact(provider = "F2FCriProvider", consumer = "IpvCoreBack")
    public MessagePact validF2fRequestReturnsIssuedEeaCardCredential(MessagePactBuilder builder)
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
                .given("VC evidence validityScore is 2")
                .given("VC evidence verificationScore is 3")
                .given("VC evidence strengthScore is 4")
                .given("VC evidence type is IdentityCheck")
                .given("VC evidence txn is eda339dd-aa83-495c-a4d4-75021e9415f9")
                .given("VC jti is test-jti")
                .expectsToReceive("A valid F2F CRI with Driving License")
                .withContent(
                        createSuccessTestEvent(
                                VALID_F2F_VC_WITH_EEA_CARD_BODY, VALID_F2F_VC_EEA_SIGNATURE))
                .toPact();
    }

    @Pact(provider = "F2FCriProvider", consumer = "IpvCoreBack")
    public MessagePact validF2fRequestReturnsIssuedBrpCredential(MessagePactBuilder builder)
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
                .given("VC evidence validityScore is 2")
                .given("VC evidence verificationScore is 3")
                .given("VC evidence strengthScore is 4")
                .given("VC evidence type is IdentityCheck")
                .given("VC evidence txn is eda339dd-aa83-495c-a4d4-75021e9415f9")
                .given("VC jti is test-jti")
                .expectsToReceive("A valid F2F CRI with BRP Document")
                .withContent(
                        createSuccessTestEvent(
                                VALID_F2F_VC_WITH_BRP_BODY, VALID_F2F_VC_BRP_SIGNATURE))
                .toPact();
    }

    @Test
    @PactTestFor(
            pactMethod = "validF2fMessageReturnsIssuedPassportCredential",
            providerType = ProviderType.ASYNCH)
    void testCallToDummyF2fIssueCredential(List<Message> messageList, MockServer mockServer)
            throws URISyntaxException {
        var verifiableCredentialJwtValidator =
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

                            } catch (Exception ignored) {
                            }
                        });
            } catch (Exception ignored) {
            }
        }
    }

    @NotNull
    private static CredentialIssuerConfig getCredentialIssuerConfig(MockServer mockServer)
            throws URISyntaxException {
        return new CredentialIssuerConfig(
                new URI("http://localhost:" + mockServer.getPort() + "/token"),
                new URI("http://localhost:" + mockServer.getPort() + "/credential"),
                new URI("http://localhost:" + mockServer.getPort() + "/authorize"),
                IPV_CORE_CLIENT_ID,
                CRI_SIGNING_PRIVATE_KEY_JWK,
                CRI_RSA_ENCRYPTION_PUBLIC_JWK,
                "dummyF2fComponentId",
                URI.create(
                        "https://identity.staging.account.gov.uk/credential-issuer/callback?id=f2f"),
                true,
                false);
    }

    private String createSuccessTestEvent(String jwtBody, String jwtSignature)
            throws JsonProcessingException {
        final CriResponseMessageDto criResponseMessageDto =
                new CriResponseMessageDto(
                        "f2f",
                        TEST_USER,
                        TEST_OAUTH_STATE,
                        List.of(new JwtBuilder(VALID_VC_HEADER, jwtBody, jwtSignature).build()),
                        null,
                        null);
        return OBJECT_MAPPER.writeValueAsString(criResponseMessageDto);
    }

    //
    @Test
    @PactTestFor(
            pactMethod = "validF2fRequestReturnsIssuedEeaCardCredential",
            providerType = ProviderType.ASYNCH)
    void eeaCardTestCallToDummyF2fIssueCredential(List<Message> messageList, MockServer mockServer)
            throws URISyntaxException {
        var verifiableCredentialJwtValidator =
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
                            } catch (Exception ignored) {
                            }
                        });
            } catch (Exception ignored) {
            }
        }
    }

    @Test
    @PactTestFor(
            pactMethod = "validF2fMessageReturnsIssuedDrivingLicenseCredential",
            providerType = ProviderType.ASYNCH)
    void drivingLicenseTestCallToDummyF2fIssueCredential(
            List<Message> messageList, MockServer mockServer) throws URISyntaxException {
        var verifiableCredentialJwtValidator =
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
                                assertEquals("DVLA", drivingLicenseNode.get(ISSUED_BY).asText());
                                assertEquals(
                                        "PARKE710112PBFGA",
                                        drivingLicenseNode.get(PERSONAL_NUMBER).asText());

                                assertEquals("1970-01-01", birthDateNode.get(VALUE).asText());

                            } catch (Exception ignored) {
                            }
                        });
            } catch (Exception ignored) {
            }
        }
    }

    @Test
    @PactTestFor(
            pactMethod = "validF2fRequestReturnsIssuedBrpCredential",
            providerType = ProviderType.ASYNCH)
    void brpTestCallToDummyF2fIssueCredential(List<Message> messageList, MockServer mockServer)
            throws URISyntaxException {
        var verifiableCredentialJwtValidator =
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

                            } catch (Exception ignored) {
                            }
                        });
            } catch (Exception ignored) {
            }
        }
    }
}
