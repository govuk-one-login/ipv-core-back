package uk.gov.di.ipv.core.processcricallback.pact.fraudCri;

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
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;

@Disabled("PACT tests should not be run in build pipelines at this time")
@ExtendWith(PactConsumerTestExt.class)
@ExtendWith(MockitoExtension.class)
@PactTestFor(providerName = "FraudCriProvider")
@MockServerConfig(hostInterface = "localhost", port = "1234")
class ContractTest {
    private static final String TEST_USER = "test-subject";
    private static final String TEST_ISSUER = "dummyFraudComponentId";
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
            "eyJpc3MiOiJpcHYtY29yZSIsInN1YiI6Imlwdi1jb3JlIiwiYXVkIjoiZHVtbXlGcmF1ZENvbXBvbmVudElkIiwiZXhwIjo0MDcwOTA5NzAwLCJqdGkiOiJTY25GNGRHWHRoWllYU181azg1T2JFb1NVMDRXLUgzcWFfcDZucHYyWlVZIn0";
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
    private static final String VALID_EXPERIAN_FRAUD_CHECK_VC_BODY =
            """
                {
                   "sub": "test-subject",
                   "iss": "dummyFraudComponentId",
                   "nbf": 4070908800,
                   "exp": 4070909400,
                   "vc": {
                        "evidence": [
                             {
                                "activityHistoryScore": 1,
                                 "checkDetails": [
                                     {
                                       "checkMethod": "data",
                                       "fraudCheck": "mortality_check"
                                     },
                                     {
                                       "checkMethod": "data",
                                       "fraudCheck": "identity_theft_check"
                                     },
                                     {
                                       "checkMethod": "data",
                                       "fraudCheck": "synthetic_identity_check"
                                     },
                                     {
                                       "checkMethod": "data",
                                       "fraudCheck": "impersonation_risk_check",
                                       "txn": "dummyTxn"
                                     },
                                     {
                                       "identityCheckPolicy": "none",
                                       "activityFrom": "2013-12-01",
                                       "checkMethod": "data"
                                     }
                                 ],
                                 "ci": [],
                                 "txn": "dummyTxn",
                                 "identityFraudScore": 2,
                                 "type": "IdentityCheck"
                             }
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
                         "address": [
                           {
                             "streetName": "HADLEY ROAD",
                             "addressType": "CURRENT",
                             "postalCode": "BA2 5AA",
                             "buildingNumber": "8",
                             "addressLocality": "BATH"
                           }
                         ]
                       }
                    }
               }
            """;
    // If we generate the signature in code it will be different each time, so we need to generate a
    // valid signature (using https://jwt.io works well) and record it here so the PACT file doesn't
    // change each time we run the tests.
    private static final String VALID_EXPERIAN_FRAUD_CHECK_VC_SIGNATURE =
            "VAN0sTEKF6mONwHpwqKvV5fPQMnoizPBaMvHxNjYjxyHJQ_UA3wRCf4lB2Ja3pPd8Jm1i_r0FFh-BX9hNrsXkw";

    private static final String FAILED_EXPERIAN_FRAUD_CHECK_VC_BODY =
            """
                {
                   "sub": "test-subject",
                   "iss": "dummyFraudComponentId",
                   "nbf": 4070908800,
                   "exp": 4070909400,
                   "vc": {
                        "evidence": [
                             {
                                "activityHistoryScore": 1,
                                 "checkDetails": [
                                     {
                                       "checkMethod": "data",
                                       "fraudCheck": "mortality_check"
                                     },
                                     {
                                       "checkMethod": "data",
                                       "fraudCheck": "identity_theft_check"
                                     },
                                     {
                                       "checkMethod": "data",
                                       "fraudCheck": "synthetic_identity_check"
                                     },
                                     {
                                       "checkMethod": "data",
                                       "fraudCheck": "impersonation_risk_check",
                                       "txn": "dummyTxn"
                                     },
                                     {
                                       "identityCheckPolicy": "none",
                                       "activityFrom": "2013-12-01",
                                       "checkMethod": "data"
                                     }
                                 ],
                                 "ci": [
                                    "P02"
                                 ],
                                 "txn": "dummyTxn",
                                 "identityFraudScore": 2,
                                 "type": "IdentityCheck"
                             }
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
                         "address": [
                           {
                             "streetName": "HADLEY ROAD",
                             "addressType": "CURRENT",
                             "postalCode": "BA2 5AA",
                             "buildingNumber": "8",
                             "addressLocality": "BATH"
                           }
                         ]
                       }
                    }
               }
            """;
    // If we generate the signature in code it will be different each time, so we need to generate a
    // valid signature (using https://jwt.io works well) and record it here so the PACT file doesn't
    // change each time we run the tests.
    private static final String FAILED_EXPERIAN_FRAUD_CHECK_VC_SIGNATURE =
            "hpLznFrXYttz_lRk2-a0_1bsjRYS7xRfU90celrXL8Bp5wppbfsOQaIOfsvBG5gQj97TErGbBKFblq0DO0mB_A";

    private static final String VALID_EXPERIAN_FRAUD_CHECK_NO_PEP_BODY =
            """
                {
                   "sub": "test-subject",
                   "iss": "dummyFraudComponentId",
                   "nbf": 4070908800,
                   "exp": 4070909400,
                   "vc": {
                        "evidence": [
                             {
                                "activityHistoryScore": 1,
                                 "checkDetails": [
                                     {
                                       "checkMethod": "data",
                                       "fraudCheck": "mortality_check"
                                     },
                                     {
                                       "checkMethod": "data",
                                       "fraudCheck": "identity_theft_check"
                                     },
                                     {
                                       "checkMethod": "data",
                                       "fraudCheck": "synthetic_identity_check"
                                     }
                                 ],
                                "failedCheckDetails": [{
                                    "txn": "dummyTxn",
                                    "checkMethod": "data",
                                    "fraudCheck": "impersonation_risk_check"
                                }],
                                "ci": [],
                                "txn": "dummyTxn",
                                "identityFraudScore": 1,
                                "type": "IdentityCheck"
                             }
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
                         "address": [
                           {
                             "streetName": "HADLEY ROAD",
                             "addressType": "CURRENT",
                             "postalCode": "BA2 5AA",
                             "buildingNumber": "8",
                             "addressLocality": "BATH"
                           }
                         ]
                       }
                    }
               }
            """;
    // If we generate the signature in code it will be different each time, so we need to generate a
    // valid signature (using https://jwt.io works well) and record it here so the PACT file doesn't
    // change each time we run the tests.
    private static final String VALID_EXPERIAN_FRAUD_CHECK_NO_PEP_SIGNATURE =
            "xydGjepcSjFsr7v2JBc2mna2PX5vEZI9VHVnAhvhcDI2HkzZKrU4j7wdc3-hJSgQVCmMbT2QOQ2uEM_8iFTPvA";

    @Mock private ConfigService mockConfigService;
    @Mock private JWSSigner mockSigner;
    @Mock private SecureTokenHelper mockSecureTokenHelper;

    @Pact(provider = "FraudCriProvider", consumer = "IpvCoreBack")
    public RequestResponsePact validRequestReturnsValidAccessToken(PactDslWithProvider builder) {
        return builder.given("dummyAuthCode is a valid authorization code")
                .given("dummyApiKey is a valid api key")
                .given("dummyFraudComponentId is the FRAUD CHECK CRI component ID")
                .given(
                        "FRAUD CRI uses CORE_BACK_SIGNING_PRIVATE_KEY_JWK to validate core signatures")
                .uponReceiving("Valid auth code")
                .path("/token")
                .method("POST")
                .body(
                        "client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer&code=dummyAuthCode&grant_type=authorization_code&redirect_uri=https%3A%2F%2Fidentity.staging.account.gov.uk%2Fcredential-issuer%2Fcallback%3Fid%3Dfraud&client_assertion="
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
    void fetchAccessToken_whenCalledAgainstFraudCri_retrievesAValidAccessToken(
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

    @Pact(provider = "FraudCriProvider", consumer = "IpvCoreBack")
    public RequestResponsePact invalidAuthCodeRequestReturns400(PactDslWithProvider builder) {
        return builder.given("dummyInvalidAuthCode is an invalid authorization code")
                .given("dummyApiKey is a valid api key")
                .given("dummyFraudComponentId is the FRAUD CHECK CRI component ID")
                .given(
                        "FRAUD CHECK CRI uses CORE_BACK_SIGNING_PRIVATE_KEY_JWK to validate core signatures")
                .uponReceiving("Invalid auth code")
                .path("/token")
                .method("POST")
                .body(
                        "client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer&code=dummyInvalidAuthCode&grant_type=authorization_code&redirect_uri=https%3A%2F%2Fidentity.staging.account.gov.uk%2Fcredential-issuer%2Fcallback%3Fid%3Dfraud&client_assertion="
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
    void fetchAccessToken_whenCalledAgainstFraudCriWithInvalidAuthCode_throwsAnException(
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

    @Pact(provider = "FraudCriProvider", consumer = "IpvCoreBack")
    public RequestResponsePact validRequestReturnsExperianFraudCheckIssuedCredential(
            PactDslWithProvider builder) {
        return builder.given("dummyApiKey is a valid api key")
                .given("dummyAccessToken is a valid access token")
                .given("test-subject is a valid subject")
                .given("dummyFraudComponentId is a valid issuer")
                .given("VC is for Kenneth Decerqueira")
                .given("VC birthDate is 1965-07-08")
                .given("VC evidence identityFraudScore is 2")
                .given("VC evidence activityHistoryScore is 1")
                .given("VC evidence txn is dummyTxn")
                .given("VC credentialSubject address streetName is HADLEY ROAD")
                .given("VC credentialSubject address addressType is CURRENT")
                .given("VC credentialSubject address postalCode is BA2 5AA")
                .given("VC credentialSubject address buildingNumber is 8")
                .given("VC credentialSubject address addressLocality is BATH")
                .given(
                        "Experian conducted mortality_check, identity_theft_check, synthetic_identity_check and impersonation_risk_check")
                .given("VC evidence activityFrom is 2013-12-01")
                .uponReceiving("Valid credential request for identity check VC")
                .path("/credential/issue")
                .method("POST")
                .headers("x-api-key", PRIVATE_API_KEY, "Authorization", "Bearer dummyAccessToken")
                .willRespondWith()
                .status(200)
                .body(
                        new PactJwtIgnoreSignatureBodyBuilder(
                                VALID_VC_HEADER,
                                VALID_EXPERIAN_FRAUD_CHECK_VC_BODY,
                                VALID_EXPERIAN_FRAUD_CHECK_VC_SIGNATURE))
                .toPact();
    }

    @Test
    @PactTestFor(pactMethod = "validRequestReturnsExperianFraudCheckIssuedCredential")
    void
            fetchVerifiableCredential_whenCalledAgainstFraudCheckCri_retrievesAValidExperianFraudCheckVc(
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
                                JsonNode addressNode = credentialSubject.get("address").get(0);

                                assertEquals("2", evidence.get("identityFraudScore").asText());

                                assertEquals("GivenName", nameParts.get(0).get("type").asText());
                                assertEquals("FamilyName", nameParts.get(1).get("type").asText());
                                assertEquals("Kenneth", nameParts.get(0).get("value").asText());
                                assertEquals("Decerqueira", nameParts.get(1).get("value").asText());

                                assertEquals("HADLEY ROAD", addressNode.get("streetName").asText());
                                assertEquals("CURRENT", addressNode.get("addressType").asText());
                                assertEquals("BA2 5AA", addressNode.get("postalCode").asText());
                                assertEquals("8", addressNode.get("buildingNumber").asText());

                                assertEquals("BATH", addressNode.get("addressLocality").asText());

                                assertEquals("1965-07-08", birthDateNode.get("value").asText());
                            } catch (VerifiableCredentialException
                                    | ParseException
                                    | JsonProcessingException e) {
                                throw new RuntimeException(e);
                            }
                        });
    }

    @Pact(provider = "FraudCriProvider", consumer = "IpvCoreBack")
    public RequestResponsePact validRequestReturnsExperianFraudCheckIssuedCredentialWithoutPepCheck(
            PactDslWithProvider builder) {
        return builder.given("dummyApiKey is a valid api key")
                .given("dummyAccessToken is a valid access token")
                .given("test-subject is a valid subject")
                .given("dummyFraudComponentId is a valid issuer")
                .given("VC is for Kenneth Decerqueira")
                .given("VC birthDate is 1965-07-08")
                .given("VC evidence identityFraudScore is 1")
                .given("VC evidence txn is dummyTxn")
                .given("VC credentialSubject address streetName is HADLEY ROAD")
                .given("VC credentialSubject address buildingName is LE FLAMBE")
                .given("VC credentialSubject address addressType is CURRENT")
                .given("VC credentialSubject address postalCode is BA2 5AA")
                .given("VC credentialSubject address buildingNumber is 8")
                .given("VC credentialSubject address addressLocality is BATH")
                .uponReceiving("Valid credential request for identity check VC")
                .path("/credential/issue")
                .method("POST")
                .headers("x-api-key", PRIVATE_API_KEY, "Authorization", "Bearer dummyAccessToken")
                .willRespondWith()
                .status(200)
                .body(
                        new PactJwtIgnoreSignatureBodyBuilder(
                                VALID_VC_HEADER,
                                VALID_EXPERIAN_FRAUD_CHECK_NO_PEP_BODY,
                                VALID_EXPERIAN_FRAUD_CHECK_NO_PEP_SIGNATURE))
                .toPact();
    }

    @Test
    @PactTestFor(
            pactMethod = "validRequestReturnsExperianFraudCheckIssuedCredentialWithoutPepCheck")
    void
            fetchVerifiableCredential_whenCalledAgainstFraudCheckCri_retrievesAValidExperianFraudCheckVc_withoutPepCheck(
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
                                JsonNode addressNode = credentialSubject.get("address").get(0);

                                assertEquals("1", evidence.get("identityFraudScore").asText());

                                assertEquals("GivenName", nameParts.get(0).get("type").asText());
                                assertEquals("FamilyName", nameParts.get(1).get("type").asText());
                                assertEquals("Kenneth", nameParts.get(0).get("value").asText());
                                assertEquals("Decerqueira", nameParts.get(1).get("value").asText());

                                assertEquals("HADLEY ROAD", addressNode.get("streetName").asText());
                                assertEquals("CURRENT", addressNode.get("addressType").asText());
                                assertEquals("BA2 5AA", addressNode.get("postalCode").asText());
                                assertEquals("8", addressNode.get("buildingNumber").asText());
                                assertEquals("BATH", addressNode.get("addressLocality").asText());

                                assertEquals("1965-07-08", birthDateNode.get("value").asText());
                            } catch (VerifiableCredentialException
                                    | ParseException
                                    | JsonProcessingException e) {
                                throw new RuntimeException(e);
                            }
                        });
    }

    @Pact(provider = "FraudCriProvider", consumer = "IpvCoreBack")
    public RequestResponsePact validRequestReturnsExperianFraudCheckResponseWithCi(
            PactDslWithProvider builder) {
        return builder.given("dummyApiKey is a valid api key")
                .given("dummyAccessToken is a valid access token")
                .given("test-subject is a valid subject")
                .given("dummyFraudComponentId is a valid issuer")
                .given("VC is for Kenneth Decerqueira")
                .given("VC birthDate is 1965-07-08")
                .given("VC evidence identityFraudScore is 1")
                .given("VC has CI of A01")
                .given("VC evidence txn is dummyTxn")
                .given("VC credentialSubject address streetName is HADLEY ROAD")
                .given("VC credentialSubject address addressType is CURRENT")
                .given("VC credentialSubject address postalCode is BA2 5AA")
                .given("VC credentialSubject address buildingNumber is 8")
                .given("VC credentialSubject address addressLocality is BATH")
                .uponReceiving("Valid credential request for identity check VC with CI")
                .path("/credential/issue")
                .method("POST")
                .headers("x-api-key", PRIVATE_API_KEY, "Authorization", "Bearer dummyAccessToken")
                .willRespondWith()
                .status(200)
                .body(
                        new PactJwtIgnoreSignatureBodyBuilder(
                                VALID_VC_HEADER,
                                FAILED_EXPERIAN_FRAUD_CHECK_VC_BODY,
                                FAILED_EXPERIAN_FRAUD_CHECK_VC_SIGNATURE))
                .toPact();
    }

    @Test
    @PactTestFor(pactMethod = "validRequestReturnsExperianFraudCheckResponseWithCi")
    void
            fetchVerifiableCredential_whenCalledAgainstFraudCheckCri_retrievesAExperianFraudCheckVcWithACi(
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
                                JsonNode addressNode = credentialSubject.get("address").get(0);

                                JsonNode ciNode = evidence.get("ci");

                                assertEquals("2", evidence.get("identityFraudScore").asText());
                                assertEquals("P02", ciNode.get(0).asText());
                                assertEquals("GivenName", nameParts.get(0).get("type").asText());
                                assertEquals("FamilyName", nameParts.get(1).get("type").asText());
                                assertEquals("Kenneth", nameParts.get(0).get("value").asText());
                                assertEquals("Decerqueira", nameParts.get(1).get("value").asText());

                                assertEquals("HADLEY ROAD", addressNode.get("streetName").asText());
                                assertEquals("CURRENT", addressNode.get("addressType").asText());
                                assertEquals("BA2 5AA", addressNode.get("postalCode").asText());
                                assertEquals("8", addressNode.get("buildingNumber").asText());

                                assertEquals("BATH", addressNode.get("addressLocality").asText());

                                assertEquals("1965-07-08", birthDateNode.get("value").asText());
                            } catch (VerifiableCredentialException
                                    | ParseException
                                    | JsonProcessingException e) {
                                throw new RuntimeException(e);
                            }
                        });
    }

    @Pact(provider = "FraudCriProvider", consumer = "IpvCoreBack")
    public RequestResponsePact invalidAccessTokenReturns403(PactDslWithProvider builder) {
        return builder.given("dummyApiKey is a valid api key")
                .given("dummyInvalidAccessToken is an invalid access token")
                .given("test-subject is a valid subject")
                .given("dummyFraudComponentId is a valid issuer")
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
    void
            fetchVerifiableCredential_whenCalledAgainstFraudCheckCriWithInvalidAccessToken_throwsAnException(
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
                "https://identity.staging.account.gov.uk/credential-issuer/callback?id=fraud",
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
        ciConfigMap.put("P02", ciConfig1);

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
                .componentId("dummyFraudComponentId")
                .clientCallbackUrl(
                        URI.create(
                                "https://identity.staging.account.gov.uk/credential-issuer/callback?id=fraud"))
                .requiresApiKey(true)
                .requiresAdditionalEvidence(false)
                .build();
    }
}
