package uk.gov.di.ipv.core.processcricallback.pact.f2fCri;

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
import com.nimbusds.oauth2.sdk.token.AccessTokenType;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
import uk.gov.di.ipv.core.library.domain.ContraIndicatorConfig;
import uk.gov.di.ipv.core.library.dto.CredentialIssuerConfig;
import uk.gov.di.ipv.core.library.dto.CriCallbackRequest;
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
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

// @Disabled("PACT tests should not be run in build pipelines at this time")
@ExtendWith(PactConsumerTestExt.class)
@ExtendWith(MockitoExtension.class)
@PactTestFor(providerName = "PassportCriProvider")
@MockServerConfig(hostInterface = "localhost", port = "1234")
public class ContractTest {
    private static final String TEST_USER = "test-subject";
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
    private static final String VALID_F2F_VC_WITH_DL_BODY =
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

    // If we generate the signature in code it will be different each time, so we need to generate a
    // valid signature (using https://jwt.io works well) and record it here so the PACT file doesn't
    // change each time we run the tests.
    private static final String VALID_F2F_VC_PASSPORT_SIGNATURE =
            "CAMtOsXoWJiNWG5JPOqRoP8Ry-3hyCRqR1VodFVSbNzsXXTn2xjQXK1J3PIxfc8ZOd9IV-TZC3gZvGty-I9CKw";
    private static final String VALID_F2F_VC_DL_SIGNATURE =
            "X5Zh-XeLVwu6RTeRWuqWW-_wNCEct2UMCrcyDbM5XBgYO02gGZGGW0zg03GTLtJCDNfK7EfduLgQo5MyjHX_TA";

    @Mock private ConfigService mockConfigService;
    @Mock private JWSSigner mockSigner;
    @Mock private SecureTokenHelper mockSecureTokenHelper;

    @Pact(provider = "F2FCriProvider", consumer = "IpvCoreBack")
    public RequestResponsePact validF2FRequestReturnsValidAccessToken(PactDslWithProvider builder) {
        return builder.given("dummyAuthCode is a valid authorization code")
                .given("dummyApiKey is a valid api key")
                .given("dummyF2fComponentId is the F2F CRI component ID")
                .given("F2F CRI uses CORE_BACK_SIGNING_PRIVATE_KEY_JWK to validate core signatures")
                .uponReceiving("Valid auth code")
                .path("/token")
                .method("POST")
                .body(
                        "client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer&code=dummyAuthCode&grant_type=authorization_code&redirect_uri=https%3A%2F%2Fidentity.staging.account.gov.uk%2Fcredential-issuer%2Fcallback%3Fid%3Df2f&client_assertion=eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJpcHYtY29yZSIsInN1YiI6Imlwdi1jb3JlIiwiYXVkIjoiZHVtbXlGMmZDb21wb25lbnRJZCIsImV4cCI6NDA3MDkwOTcwMCwianRpIjoiU2NuRjRkR1h0aFpZWFNfNWs4NU9iRW9TVTA0Vy1IM3FhX3A2bnB2MlpVWSJ9.hXYrKJ_W9YItUbZxu3T63gQgScVoSMqHZ43UPfdB8im8L4d0mZPLC6BlwMJSsfjiAyU1y3c37vm-rV8kZo2uyw")
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

    @Pact(provider = "F2FCriProvider", consumer = "IpvCoreBack")
    public RequestResponsePact validF2fRequestReturnsIssuedPassportCredential(
            PactDslWithProvider builder) throws Exception {
        return builder.given("dummyApiKey is a valid api key")
                .given("dummyAccessToken is a valid access token")
                .given("test-subject is a valid subject")
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
                .uponReceiving("Valid POST request")
                .path("/credential")
                .method("POST")
                .headers("x-api-key", PRIVATE_API_KEY, "Authorization", "Bearer dummyAccessToken")
                .willRespondWith()
                .status(200)
                .body(
                        new PactJwtIgnoreSignatureBodyBuilder(
                                VALID_VC_HEADER,
                                VALID_F2F_VC_WITH_PASSPORT_BODY,
                                VALID_F2F_VC_PASSPORT_SIGNATURE))
                .toPact();
    }

    @Pact(provider = "F2FCriProvider", consumer = "IpvCoreBack")
    public RequestResponsePact validF2fRequestReturnsIssuedDrivingLicenseCredential(
            PactDslWithProvider builder) throws Exception {
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
                .uponReceiving("Valid POST request")
                .path("/credential")
                .method("POST")
                .headers("x-api-key", PRIVATE_API_KEY, "Authorization", "Bearer dummyAccessToken")
                .willRespondWith()
                .status(200)
                .body(
                        new PactJwtIgnoreSignatureBodyBuilder(
                                VALID_VC_HEADER,
                                VALID_F2F_VC_WITH_DL_BODY,
                                VALID_F2F_VC_DL_SIGNATURE))
                .toPact();
    }

    @Test
    @PactTestFor(pactMethod = "validF2FRequestReturnsValidAccessToken")
    void fetchAccessToken_whenCalledAgainstF2FCri_retrievesAValidAccessToken(MockServer mockServer)
            throws URISyntaxException, JOSEException, CriApiException {
        // Arrange
        var credentialIssuerConfig = getMockF2FCredentialIssuerConfig(mockServer);

        when(mockConfigService.getSsmParameter(ConfigurationVariable.JWT_TTL_SECONDS))
                .thenReturn("900");
        when(mockConfigService.getCriConfig(any())).thenReturn(credentialIssuerConfig);
        when(mockConfigService.getCriPrivateApiKey(any())).thenReturn(PRIVATE_API_KEY);

        // Signature generated by jwt.io by debugging the test and getting the client assertion JWT
        // generated by the test as mocking out the AWSKMS class inside the real signer would be
        // painful.
        when(mockSigner.sign(any(), any()))
                .thenReturn(
                        new Base64URL(
                                "hXYrKJ_W9YItUbZxu3T63gQgScVoSMqHZ43UPfdB8im8L4d0mZPLC6BlwMJSsfjiAyU1y3c37vm-rV8kZo2uyw"));
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
                        new CriCallbackRequest(
                                "dummyAuthCode",
                                credentialIssuerConfig.getClientId(),
                                "dummySessionId",
                                "https://identity.staging.account.gov.uk/credential-issuer/callback?id=f2f",
                                "dummyState",
                                null,
                                null,
                                "dummyIpAddress",
                                "dummyFeatureSet"),
                        new CriOAuthSessionItem(
                                "dummySessionId",
                                "dummyOAuthSessionId",
                                "dummyCriId",
                                "dummyConnection",
                                900));
        // Assert
        assertThat(accessToken.getType(), is(AccessTokenType.BEARER));
        assertThat(accessToken.getValue(), notNullValue());
        assertThat(accessToken.getLifetime(), greaterThan(0L));
    }

    @Test
    @PactTestFor(pactMethod = "validF2fRequestReturnsIssuedPassportCredential")
    void testCallToDummyF2fIssueCredential(MockServer mockServer)
            throws URISyntaxException, CriApiException {
        // Arrange
        var credentialIssuerConfig = getMockF2FCredentialIssuerConfig(mockServer);

        ContraIndicatorConfig ciConfig1 = new ContraIndicatorConfig(null, 4, null, null);
        ContraIndicatorConfig ciConfig2 = new ContraIndicatorConfig(null, 4, null, null);

        Map<String, ContraIndicatorConfig> ciConfigMap = new HashMap<>();
        ciConfigMap.put("A02", ciConfig1);
        ciConfigMap.put("A03", ciConfig2);

        when(mockConfigService.getCriConfig(any())).thenReturn(credentialIssuerConfig);
        when(mockConfigService.getCriPrivateApiKey(any())).thenReturn(PRIVATE_API_KEY);
        when(mockConfigService.getContraIndicatorConfigMap()).thenReturn(ciConfigMap);

        var verifiableCredentialJwtValidator =
                new VerifiableCredentialJwtValidator(
                        mockConfigService,
                        ((exactMatchClaims, requiredClaims) ->
                                new FixedTimeJWTClaimsVerifier<>(
                                        exactMatchClaims,
                                        requiredClaims,
                                        Date.from(CURRENT_TIME.instant()))));

        // We need to generate a fixed request, so we set the secure token and expiry to constant
        // values.
        var underTest =
                new CriApiService(
                        mockConfigService, mockSigner, mockSecureTokenHelper, CURRENT_TIME);

        // Act
        var verifiableCredentialResponse =
                underTest.fetchVerifiableCredential(
                        new BearerAccessToken("dummyAccessToken"),
                        new CriCallbackRequest(
                                "dummyAuthCode",
                                credentialIssuerConfig.getClientId(),
                                "dummySessionId",
                                "https://identity.staging.account.gov.uk/credential-issuer/callback?id=f2f",
                                "dummyState",
                                null,
                                null,
                                "dummyIpAddress",
                                "dummyFeatureSet"),
                        new CriOAuthSessionItem(
                                "dummySessionId",
                                "dummyOAuthSessionId",
                                "dummyCriId",
                                "dummyConnection",
                                900));

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

                                JsonNode nameParts =
                                        credentialSubject.get("name").get(0).get("nameParts");
                                JsonNode birthDateNode = credentialSubject.get("birthDate").get(0);
                                JsonNode passportNode = credentialSubject.get("passport").get(0);

                                assertEquals("GivenName", nameParts.get(0).get("type").asText());
                                assertEquals("FamilyName", nameParts.get(1).get("type").asText());
                                assertEquals("Kenneth", nameParts.get(0).get("value").asText());
                                assertEquals("Decerqueira", nameParts.get(1).get("value").asText());

                                assertEquals("2030-01-01", passportNode.get("expiryDate").asText());
                                assertEquals(
                                        "321654987", passportNode.get("documentNumber").asText());

                                assertEquals("1965-07-08", birthDateNode.get("value").asText());
                            } catch (VerifiableCredentialException
                                    | ParseException
                                    | JsonProcessingException e) {
                                throw new RuntimeException(e);
                            }
                        });
    }

    @Test
    @PactTestFor(pactMethod = "validF2fRequestReturnsIssuedDrivingLicenseCredential")
    void drivingLicenseTestCallToDummyF2fIssueCredential(MockServer mockServer)
            throws URISyntaxException, CriApiException {
        // Arrange
        var credentialIssuerConfig = getMockF2FCredentialIssuerConfig(mockServer);

        ContraIndicatorConfig ciConfig1 = new ContraIndicatorConfig(null, 4, null, null);
        ContraIndicatorConfig ciConfig2 = new ContraIndicatorConfig(null, 4, null, null);

        Map<String, ContraIndicatorConfig> ciConfigMap = new HashMap<>();
        ciConfigMap.put("A02", ciConfig1);
        ciConfigMap.put("A03", ciConfig2);

        when(mockConfigService.getCriConfig(any())).thenReturn(credentialIssuerConfig);
        when(mockConfigService.getCriPrivateApiKey(any())).thenReturn(PRIVATE_API_KEY);
        when(mockConfigService.getContraIndicatorConfigMap()).thenReturn(ciConfigMap);

        var verifiableCredentialJwtValidator =
                new VerifiableCredentialJwtValidator(
                        mockConfigService,
                        ((exactMatchClaims, requiredClaims) ->
                                new FixedTimeJWTClaimsVerifier<>(
                                        exactMatchClaims,
                                        requiredClaims,
                                        Date.from(CURRENT_TIME.instant()))));

        // We need to generate a fixed request, so we set the secure token and expiry to constant
        // values.
        var underTest =
                new CriApiService(
                        mockConfigService, mockSigner, mockSecureTokenHelper, CURRENT_TIME);

        // Act
        var verifiableCredentialResponse =
                underTest.fetchVerifiableCredential(
                        new BearerAccessToken("dummyAccessToken"),
                        new CriCallbackRequest(
                                "dummyAuthCode",
                                credentialIssuerConfig.getClientId(),
                                "dummySessionId",
                                "https://identity.staging.account.gov.uk/credential-issuer/callback?id=f2f",
                                "dummyState",
                                null,
                                null,
                                "dummyIpAddress",
                                "dummyFeatureSet"),
                        new CriOAuthSessionItem(
                                "dummySessionId",
                                "dummyOAuthSessionId",
                                "dummyCriId",
                                "dummyConnection",
                                900));

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

                                JsonNode nameParts =
                                        credentialSubject.get("name").get(0).get("nameParts");
                                JsonNode birthDateNode = credentialSubject.get("birthDate").get(0);
                                JsonNode drivingLicenseNode = credentialSubject.get("drivingPermit").get(0);

                                assertEquals("GivenName", nameParts.get(0).get("type").asText());
                                assertEquals("GivenName", nameParts.get(1).get("type").asText());
                                assertEquals("FamilyName", nameParts.get(2).get("type").asText());

                                assertEquals("Alice", nameParts.get(0).get("value").asText());
                                assertEquals("Jane", nameParts.get(1).get("value").asText());
                                assertEquals("Parker", nameParts.get(2).get("value").asText());

                                assertEquals("2032-02-02", drivingLicenseNode.get("expiryDate").asText());
                                assertEquals("2005-02-02", drivingLicenseNode.get("issueDate").asText());
                                assertEquals("DVLA", drivingLicenseNode.get("issuedBy").asText());
                                assertEquals(
                                        "PARKE710112PBFGA", drivingLicenseNode.get("personalNumber").asText());

                                assertEquals("1970-01-01", birthDateNode.get("value").asText());
                            } catch (VerifiableCredentialException
                                    | ParseException
                                    | JsonProcessingException e) {
                                throw new RuntimeException(e);
                            }
                        });
    }

    @NotNull
    private static CredentialIssuerConfig getMockF2FCredentialIssuerConfig(MockServer mockServer)
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
}
