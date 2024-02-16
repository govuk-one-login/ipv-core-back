package uk.gov.di.ipv.core.processcricallback.pact.ninoCri;

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

@Disabled("PACT tests should not be run in build pipelines at this time")
@ExtendWith(PactConsumerTestExt.class)
@ExtendWith(MockitoExtension.class)
@PactTestFor(providerName = "NinoCriProvider")
@MockServerConfig(hostInterface = "localhost", port = "1234")
class ContractTest {
    private static final String TEST_USER = "test-subject";
    private static final String TEST_ISSUER = "dummyNinoComponentId";
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
            "eyJpc3MiOiJpcHYtY29yZSIsInN1YiI6Imlwdi1jb3JlIiwiYXVkIjoiZHVtbXlOaW5vQ29tcG9uZW50SWQiLCJleHAiOjQwNzA5MDk3MDAsImp0aSI6IlNjbkY0ZEdYdGhaWVhTXzVrODVPYkVvU1UwNFctSDNxYV9wNm5wdjJaVVkifQ";
    // Signature generated using JWT.io
    private static final String CLIENT_ASSERTION_SIGNATURE =
            "ZHj3_BoW2CJEsWA7i_Eq0tfi3HsmoHonHVmBaY7OAzOn-ZA_MYcIaRuMOCipK4_Ar1hCT1LMYveJrD0aYs1y0Q";

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
    private static final String VALID_NINO_IDENTITY_CHECK_VC_BODY =
            """
        {
           "sub": "test-subject",
           "iss": "dummyNinoComponentId",
           "nbf": 4070908800,
           "exp": 4070909400,
           "vc": {
             "evidence": [
               {
                 "activityHistoryScore": 1,
                 "checkDetails": [
                   {
                     "checkMethod": "data"
                   }
                 ],
                 "validityScore": 2,
                 "strengthScore": 2,
                 "type": "IdentityCheck",
                 "txn": "dummyTxn"
               }
             ],
             "credentialSubject": {
               "socialSecurityRecord": [
                 {
                   "personalNumber": "AA000003D"
                 }
               ],
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
               ]
             },
             "type": [
               "VerifiableCredential",
               "IdentityCheckCredential"
             ]
           },
           "jti":"dummyJti"
         }
    """;
    // If we generate the signature in code it will be different each time, so we need to generate a
    // valid signature (using https://jwt.io works well) and record it here so the PACT file doesn't
    // change each time we run the tests.
    private static final String VALID_NINO_IDENTITY_CHECK_VC_SIGNATURE =
            "WHEg4EooDiCdT676GPVE4l4z5YY-Tvl3FTY4bYI_nCzx8mqrg2rTYJUM4SG8azbyBjdSG8UQFyfAuLPeYlMTwg";

    private static final String FAILED_NINO_IDENTITY_CHECK_VC_BODY =
            """
            {
                "sub": "test-subject",
                "iss": "dummyNinoComponentId",
                "nbf": 4070908800,
                "exp": 4070909400,
                "vc": {
                 "evidence": [
                   {
                     "failedCheckDetails": [
                       {
                         "checkMethod": "data"
                       }
                     ],
                     "validityScore": 0,
                     "strengthScore": 2,
                     "ci": [
                        "D02"
                     ],
                     "type": "IdentityCheck",
                     "txn": "dummyTxn"
                   }
                 ],
                 "credentialSubject": {
                   "socialSecurityRecord": [
                     {
                       "personalNumber": "AA000003D"
                     }
                   ],
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
                   ]
                 },
                 "type": [
                   "VerifiableCredential",
                   "IdentityCheckCredential"
                 ]
                },
                "jti":"dummyJti"
                }
            """;
    // If we generate the signature in code it will be different each time, so we need to generate a
    // valid signature (using https://jwt.io works well) and record it here so the PACT file doesn't
    // change each time we run the tests.
    private static final String FAILED_NINO_IDENTITY_CHECK_VC_SIGNATURE =
            "GdAM1VaIj5fPZD-8mosORKfbqazER2xNzS2wJ-3ksq2HsCLujvK6kTSjER1OxMHTXH4T8wEROVbGIVeaK9vY9A";

    private static final String VALID_NINO_VC_BODY =
            """
        {
           "sub": "test-subject",
           "iss": "dummyNinoComponentId",
           "nbf": 4070908800,
           "exp": 4070909400,
           "vc": {
             "evidence": [
               {
                 "checkDetails": [
                   {
                     "checkMethod": "data"
                   }
                 ],
                 "type": "IdentityCheck",
                 "txn": "dummyTxn"
               }
             ],
             "credentialSubject": {
               "socialSecurityRecord": [
                 {
                   "personalNumber": "AA000003D"
                 }
               ],
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
               ]
             },
             "type": [
               "VerifiableCredential",
               "IdentityCheckCredential"
             ]
           },
           "jti":"dummyJti"
         }
    """;
    // If we generate the signature in code it will be different each time, so we need to generate a
    // valid signature (using https://jwt.io works well) and record it here so the PACT file doesn't
    // change each time we run the tests.
    private static final String VALID_NINO_VC_SIGNATURE =
            "WjlFHK3oFx1Wbi1aQ380OJs3Br-aZWCjUsa-BXOg-LnTzdhExZnS2OQ-fckweGzfvZFnuZcC0R8IML6axALGpg";

    private static final String FAILED_NINO_VC_BODY =
            """
            {
                "sub": "test-subject",
                "iss": "dummyNinoComponentId",
                "nbf": 4070908800,
                "exp": 4070909400,
                "vc": {
                 "evidence": [
                   {
                     "failedCheckDetails": [
                       {
                         "checkMethod": "data"
                       }
                     ],
                     "ci": [
                        "D02"
                     ],
                     "type": "IdentityCheck",
                     "txn": "dummyTxn"
                   }
                 ],
                 "credentialSubject": {
                   "socialSecurityRecord": [
                     {
                       "personalNumber": "AA000003D"
                     }
                   ],
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
                   ]
                 },
                 "type": [
                   "VerifiableCredential",
                   "IdentityCheckCredential"
                 ]
                },
                "jti":"dummyJti"
                }
            """;
    // If we generate the signature in code it will be different each time, so we need to generate a
    // valid signature (using https://jwt.io works well) and record it here so the PACT file doesn't
    // change each time we run the tests.
    private static final String FAILED_NINO_VC_SIGNATURE =
            "oC40cHPwnkvFecAzGDpR_Ht6wL34YDmMcTn05pi2mkP19BRgnjIw47ccZqbjYfYdEVEv6IzyYclEVgBd66G-Aw";

    @Mock private ConfigService mockConfigService;
    @Mock private JWSSigner mockSigner;
    @Mock private SecureTokenHelper mockSecureTokenHelper;

    @Pact(provider = "NinoCriProvider", consumer = "IpvCoreBack")
    public RequestResponsePact validRequestReturnsValidAccessToken(PactDslWithProvider builder) {
        return builder.given("dummyAuthCode is a valid authorization code")
                .given("dummyApiKey is a valid api key")
                .given("dummyNinoComponentId is the NINO CRI component ID")
                .given(
                        "NINO CRI uses CORE_BACK_SIGNING_PRIVATE_KEY_JWK to validate core signatures")
                .uponReceiving("Valid auth code")
                .path("/token")
                .method("POST")
                .body(
                        "client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer&code=dummyAuthCode&grant_type=authorization_code&redirect_uri=https%3A%2F%2Fidentity.staging.account.gov.uk%2Fcredential-issuer%2Fcallback%3Fid%3Dnino&client_assertion="
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
    void fetchAccessToken_whenCalledAgainstNinoCri_retrievesAValidAccessToken(MockServer mockServer)
            throws URISyntaxException, JOSEException, CriApiException {
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

    @Pact(provider = "NinoCriProvider", consumer = "IpvCoreBack")
    public RequestResponsePact invalidAuthCodeRequestReturns400(PactDslWithProvider builder) {
        return builder.given("dummyInvalidAuthCode is an invalid authorization code")
                .given("dummyApiKey is a valid api key")
                .given("dummyNinoComponentId is the NINO CRI component ID")
                .given(
                        "NINO CRI uses CORE_BACK_SIGNING_PRIVATE_KEY_JWK to validate core signatures")
                .uponReceiving("Invalid auth code")
                .path("/token")
                .method("POST")
                .body(
                        "client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer&code=dummyInvalidAuthCode&grant_type=authorization_code&redirect_uri=https%3A%2F%2Fidentity.staging.account.gov.uk%2Fcredential-issuer%2Fcallback%3Fid%3Dnino&client_assertion="
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
    void fetchAccessToken_whenCalledAgainstNinoCriWithInvalidAuthCode_throwsAnException(
            MockServer mockServer) throws URISyntaxException, JOSEException {
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

    @Pact(provider = "NinoCriProvider", consumer = "IpvCoreBack")
    public RequestResponsePact validRequestReturnsNinoIdentityCheckIssuedCredential(
            PactDslWithProvider builder) {
        return builder.given("dummyApiKey is a valid api key")
                .given("dummyAccessToken is a valid access token")
                .given("test-subject is a valid subject")
                .given("dummyNinoComponentId is a valid issuer")
                .given("VC evidence activityHistoryScore is 1")
                .given("VC is for Kenneth Decerqueira")
                .given("VC evidence validityScore is 2")
                .given("VC evidence strengthScore is 2")
                .given("VC evidence txn is dummyTxn")
                .given("VC contains a socialSecurityRecord")
                .given("VC personalNumber is AA000003D")
                .given("VC jti is dummyJti")
                .given("VC birthDate is 1965-07-08")
                .uponReceiving("Valid credential request for identity check VC")
                .path("/credential/issue")
                .method("POST")
                .headers("x-api-key", PRIVATE_API_KEY, "Authorization", "Bearer dummyAccessToken")
                .willRespondWith()
                .status(200)
                .body(
                        new PactJwtIgnoreSignatureBodyBuilder(
                                VALID_VC_HEADER,
                                VALID_NINO_IDENTITY_CHECK_VC_BODY,
                                VALID_NINO_IDENTITY_CHECK_VC_SIGNATURE))
                .toPact();
    }

    @Test
    @PactTestFor(pactMethod = "validRequestReturnsNinoIdentityCheckIssuedCredential")
    void fetchVerifiableCredential_whenCalledAgainstNinoCri_retrievesAValidIdentityCheckVc(
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

                                JsonNode credentialSubject =
                                        objectMapper
                                                .readTree(credential.getJWTClaimsSet().toString())
                                                .get("vc")
                                                .get("credentialSubject");

                                JsonNode vc =
                                        objectMapper
                                                .readTree(credential.getJWTClaimsSet().toString())
                                                .get("vc");

                                JsonNode evidence = vc.get("evidence").get(0);

                                JsonNode nameParts =
                                        credentialSubject.get("name").get(0).get("nameParts");
                                JsonNode birthDateNode = credentialSubject.get("birthDate").get(0);
                                JsonNode socialSecurityRecordNode =
                                        credentialSubject.get("socialSecurityRecord").get(0);

                                assertEquals("2", evidence.get("strengthScore").asText());
                                assertEquals("2", evidence.get("validityScore").asText());

                                assertEquals("GivenName", nameParts.get(0).get("type").asText());
                                assertEquals("FamilyName", nameParts.get(1).get("type").asText());
                                assertEquals("Kenneth", nameParts.get(0).get("value").asText());
                                assertEquals("Decerqueira", nameParts.get(1).get("value").asText());

                                assertEquals(
                                        "AA000003D",
                                        socialSecurityRecordNode.get("personalNumber").asText());

                                assertEquals("1965-07-08", birthDateNode.get("value").asText());
                            } catch (VerifiableCredentialException
                                    | ParseException
                                    | JsonProcessingException e) {
                                throw new RuntimeException(e);
                            }
                        });
    }

    @Pact(provider = "NinoCriProvider", consumer = "IpvCoreBack")
    public RequestResponsePact validRequestReturnsNinoIdentityCheckResponseWithCi(
            PactDslWithProvider builder) {
        return builder.given("dummyApiKey is a valid api key")
                .given("dummyAccessToken is a valid access token")
                .given("test-subject is a valid subject")
                .given("dummyNinoComponentId is a valid issuer")
                .given("VC has a CI of D02")
                .given("VC evidence activityHistoryScore is 1")
                .given("VC is for Kenneth Decerqueira")
                .given("VC evidence validityScore is 0")
                .given("VC evidence strengthScore is 2")
                .given("VC evidence txn is dummyTxn")
                .given("VC contains a socialSecurityRecord")
                .given("VC personalNumber is AA000003D")
                .given("VC jti is dummyJti")
                .given("VC birthDate is 1965-07-08")
                .uponReceiving("Valid credential request for identity check VC with CI")
                .path("/credential/issue")
                .method("POST")
                .headers("x-api-key", PRIVATE_API_KEY, "Authorization", "Bearer dummyAccessToken")
                .willRespondWith()
                .status(200)
                .body(
                        new PactJwtIgnoreSignatureBodyBuilder(
                                VALID_VC_HEADER,
                                FAILED_NINO_IDENTITY_CHECK_VC_BODY,
                                FAILED_NINO_IDENTITY_CHECK_VC_SIGNATURE))
                .toPact();
    }

    @Test
    @PactTestFor(pactMethod = "validRequestReturnsNinoIdentityCheckResponseWithCi")
    void fetchVerifiableCredential_whenCalledAgainstNinoCri_retrievesANinoIdentityCheckVcWithACi(
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

                                JsonNode evidence = vc.get("evidence").get(0);
                                JsonNode credentialSubject = vc.get("credentialSubject");

                                JsonNode ciNode = evidence.get("ci");
                                JsonNode nameParts =
                                        credentialSubject.get("name").get(0).get("nameParts");
                                JsonNode birthDateNode = credentialSubject.get("birthDate").get(0);

                                assertEquals("D02", ciNode.get(0).asText());

                                JsonNode socialSecurityRecordNode =
                                        credentialSubject.get("socialSecurityRecord").get(0);

                                assertEquals("GivenName", nameParts.get(0).get("type").asText());
                                assertEquals("FamilyName", nameParts.get(1).get("type").asText());
                                assertEquals("Kenneth", nameParts.get(0).get("value").asText());
                                assertEquals("Decerqueira", nameParts.get(1).get("value").asText());

                                assertEquals("2", evidence.get("strengthScore").asText());
                                assertEquals("0", evidence.get("validityScore").asText());

                                assertEquals(
                                        "AA000003D",
                                        socialSecurityRecordNode.get("personalNumber").asText());

                                assertEquals("1965-07-08", birthDateNode.get("value").asText());
                            } catch (VerifiableCredentialException
                                    | ParseException
                                    | JsonProcessingException e) {
                                throw new RuntimeException(e);
                            }
                        });
    }

    @Pact(provider = "NinoCriProvider", consumer = "IpvCoreBack")
    public RequestResponsePact validRequestReturnsNinoIssuedCredential(
            PactDslWithProvider builder) {
        return builder.given("dummyApiKey is a valid api key")
                .given("dummyAccessToken is a valid access token")
                .given("test-subject is a valid subject")
                .given("dummyNinoComponentId is a valid issuer")
                .given("VC evidence activityHistoryScore is 1")
                .given("VC is for Kenneth Decerqueira")
                .given("VC evidence validityScore is 2")
                .given("VC evidence strengthScore is 2")
                .given("VC evidence txn is dummyTxn")
                .given("VC contains a socialSecurityRecord")
                .given("VC personalNumber is AA000003D")
                .given("VC jti is dummyJti")
                .given("VC birthDate is 1965-07-08")
                .uponReceiving("Valid credential request for VC")
                .path("/credential/issue")
                .method("POST")
                .headers("x-api-key", PRIVATE_API_KEY, "Authorization", "Bearer dummyAccessToken")
                .willRespondWith()
                .status(200)
                .body(
                        new PactJwtIgnoreSignatureBodyBuilder(
                                VALID_VC_HEADER, VALID_NINO_VC_BODY, VALID_NINO_VC_SIGNATURE))
                .toPact();
    }

    @Test
    @PactTestFor(pactMethod = "validRequestReturnsNinoIssuedCredential")
    void fetchVerifiableCredential_whenCalledAgainstNinoCri_retrievesAValidVc(MockServer mockServer)
            throws URISyntaxException, CriApiException {
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

                                JsonNode credentialSubject =
                                        objectMapper
                                                .readTree(credential.getJWTClaimsSet().toString())
                                                .get("vc")
                                                .get("credentialSubject");

                                JsonNode nameParts =
                                        credentialSubject.get("name").get(0).get("nameParts");
                                JsonNode birthDateNode = credentialSubject.get("birthDate").get(0);
                                JsonNode socialSecurityRecordNode =
                                        credentialSubject.get("socialSecurityRecord").get(0);

                                assertEquals("GivenName", nameParts.get(0).get("type").asText());
                                assertEquals("FamilyName", nameParts.get(1).get("type").asText());
                                assertEquals("Kenneth", nameParts.get(0).get("value").asText());
                                assertEquals("Decerqueira", nameParts.get(1).get("value").asText());

                                assertEquals(
                                        "AA000003D",
                                        socialSecurityRecordNode.get("personalNumber").asText());

                                assertEquals("1965-07-08", birthDateNode.get("value").asText());
                            } catch (VerifiableCredentialException
                                    | ParseException
                                    | JsonProcessingException e) {
                                throw new RuntimeException(e);
                            }
                        });
    }

    @Pact(provider = "NinoCriProvider", consumer = "IpvCoreBack")
    public RequestResponsePact validRequestReturnsNinoResponseWithCi(PactDslWithProvider builder) {
        return builder.given("dummyApiKey is a valid api key")
                .given("dummyAccessToken is a valid access token")
                .given("test-subject is a valid subject")
                .given("dummyNinoComponentId is a valid issuer")
                .given("VC has a CI of D02")
                .given("VC evidence activityHistoryScore is 1")
                .given("VC is for Kenneth Decerqueira")
                .given("VC evidence validityScore is 0")
                .given("VC evidence strengthScore is 2")
                .given("VC evidence txn is dummyTxn")
                .given("VC contains a socialSecurityRecord")
                .given("VC personalNumber is AA000003D")
                .given("VC jti is dummyJti")
                .given("VC birthDate is 1965-07-08")
                .uponReceiving("Valid credential request for VC with CI")
                .path("/credential/issue")
                .method("POST")
                .headers("x-api-key", PRIVATE_API_KEY, "Authorization", "Bearer dummyAccessToken")
                .willRespondWith()
                .status(200)
                .body(
                        new PactJwtIgnoreSignatureBodyBuilder(
                                VALID_VC_HEADER, FAILED_NINO_VC_BODY, FAILED_NINO_VC_SIGNATURE))
                .toPact();
    }

    @Test
    @PactTestFor(pactMethod = "validRequestReturnsNinoResponseWithCi")
    void fetchVerifiableCredential_whenCalledAgainstNinoCri_retrievesANinoVcWithACi(
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

                                assertEquals("D02", ciNode.get(0).asText());

                                JsonNode socialSecurityRecordNode =
                                        credentialSubject.get("socialSecurityRecord").get(0);

                                assertEquals("GivenName", nameParts.get(0).get("type").asText());
                                assertEquals("FamilyName", nameParts.get(1).get("type").asText());
                                assertEquals("Kenneth", nameParts.get(0).get("value").asText());
                                assertEquals("Decerqueira", nameParts.get(1).get("value").asText());

                                assertEquals(
                                        "AA000003D",
                                        socialSecurityRecordNode.get("personalNumber").asText());

                                assertEquals("1965-07-08", birthDateNode.get("value").asText());
                            } catch (VerifiableCredentialException
                                    | ParseException
                                    | JsonProcessingException e) {
                                throw new RuntimeException(e);
                            }
                        });
    }

    @Pact(provider = "NinoCriProvider", consumer = "IpvCoreBack")
    public RequestResponsePact invalidAccessTokenReturns403(PactDslWithProvider builder) {
        return builder.given("dummyApiKey is a valid api key")
                .given("dummyInvalidAccessToken is an invalid access token")
                .given("test-subject is a valid subject")
                .given("dummyNinoComponentId is a valid issuer")
                .uponReceiving("Invalid POST request due to invalid access token")
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
    void fetchVerifiableCredential_whenCalledAgainstNinoCriWithInvalidAccessToken_throwsAnException(
            MockServer mockServer) throws URISyntaxException {
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
                "https://identity.staging.account.gov.uk/credential-issuer/callback?id=nino",
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
                .componentId("dummyNinoComponentId")
                .clientCallbackUrl(
                        URI.create(
                                "https://identity.staging.account.gov.uk/credential-issuer/callback?id=nino"))
                .requiresApiKey(true)
                .requiresAdditionalEvidence(false)
                .build();
    }
}
