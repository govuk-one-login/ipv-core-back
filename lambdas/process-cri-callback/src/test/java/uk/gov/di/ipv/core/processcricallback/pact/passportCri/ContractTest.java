package uk.gov.di.ipv.core.processcricallback.pact.passportCri;

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
@PactTestFor(providerName = "PassportCriProvider")
@MockServerConfig(hostInterface = "localhost", port = "1234")
class ContractTest {
    private static final String TEST_USER = "test-subject";
    private static final String IPV_CORE_CLIENT_ID = "ipv-core";
    private static final String PRIVATE_API_KEY = "dummyApiKey";
    public static final String CRI_COMPONENT_ID = "dummyPassportComponentId";
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
            "eyJpc3MiOiJpcHYtY29yZSIsInN1YiI6Imlwdi1jb3JlIiwiYXVkIjoiZHVtbXlQYXNzcG9ydENvbXBvbmVudElkIiwiZXhwIjo0MDcwOTA5NzAwLCJqdGkiOiJTY25GNGRHWHRoWllYU181azg1T2JFb1NVMDRXLUgzcWFfcDZucHYyWlVZIn0";
    // Signature generated using JWT.io
    private static final String CLIENT_ASSERTION_SIGNATURE =
            "8_p0JKL8REQI7GXwqMs2qdKyDNstjUDv0RUgZc37LmdtFvIib317AbSbC9tM_J_YXI6pmhksuLvZJ_3fFNOJtg";

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
    private static final String VALID_VC_BODY =
            """
            {
                "iss": "dummyPassportComponentId",
                "sub": "test-subject",
                "nbf": 4070908800,
                "vc": {
                    "type": [
                        "VerifiableCredential",
                        "IdentityCheckCredential"
                    ],
                    "credentialSubject": {
                        "birthDate": [
                            {
                                "value": "1932-02-25"
                            }
                        ],
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
                        "passport": [
                            {
                                "documentNumber": "824159121",
                                "icaoIssuerCode": "GBR",
                                "expiryDate": "2030-01-01"
                            }
                        ]
                    },
                    "evidence": [
                        {
                            "type": "IdentityCheck",
                            "txn": "278450f1-75f5-4d0d-9e8e-8bc37a07248d",
                            "strengthScore": 4,
                            "validityScore": 2,
                            "ci": [],
                            "checkDetails": [
                                {
                                    "checkMethod": "data",
                                    "dataCheck": "scenario_1"
                                },
                                {
                                    "checkMethod": "data",
                                    "dataCheck": "record_check"
                                }
                            ],
                            "ciReasons": []
                        }
                    ]
                }
            }
            """;
    // If we generate the signature in code it will be different each time, so we need to generate a
    // valid signature (using https://jwt.io works well) and record it here so the PACT file doesn't
    // change each time we run the tests.
    private static final String VALID_VC_SIGNATURE =
            "qqRxw3jYdhlirU86WNur3IN-SXwXTULRDNTwlhJOQQB1z2lErfwOiY-cI2HH7mLrUkYGyf_MDGV0uPU1BpuL0Q";

    private static final String FAILED_VC_BODY =
            """
            {
                "iss": "dummyPassportComponentId",
                "sub": "test-subject",
                "nbf": 4070908800,
                "vc": {
                    "type": [
                        "VerifiableCredential",
                        "IdentityCheckCredential"
                    ],
                    "credentialSubject": {
                        "birthDate": [
                            {
                                "value": "1932-02-25"
                            }
                        ],
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
                        "passport": [
                            {
                                "documentNumber": "123456789",
                                "icaoIssuerCode": "GBR",
                                "expiryDate": "2030-01-01"
                            }
                        ]
                    },
                    "evidence": [
                        {
                            "type": "IdentityCheck",
                            "txn": "278450f1-75f5-4d0d-9e8e-8bc37a07248d",
                            "strengthScore": 4,
                            "validityScore": 0,
                            "ci": [
                                "D02"
                            ],
                            "failedCheckDetails": [
                                {
                                    "checkMethod": "data",
                                    "dataCheck": "record_check"
                                }
                            ],
                            "ciReasons": [
                                {
                                    "ci": "D02",
                                    "reason": "NoMatchingRecord"
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
    private static final String FAILED_VC_SIGNATURE =
            "CE2iR-txy0niAgSE_Huzn5J7Kg9MEmR9FHH8V7loSEjM6-YkHnUqRGbncZRGupoISDMAOhSPpHYlK1DoBNiZ4Q";

    private static final String FAILED_VC_SCENARIO_2_BODY =
            """
            {
                "iss": "dummyPassportComponentId",
                "sub": "test-subject",
                "nbf": 4070908800,
                "vc": {
                    "type": [
                        "VerifiableCredential",
                        "IdentityCheckCredential"
                    ],
                    "credentialSubject": {
                        "birthDate": [
                            {
                                "value": "1932-02-25"
                            }
                        ],
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
                        "passport": [
                            {
                                "documentNumber": "123456789",
                                "icaoIssuerCode": "GBR",
                                "expiryDate": "2030-01-01"
                            }
                        ]
                    },
                    "evidence": [
                        {
                            "type": "IdentityCheck",
                            "txn": "278450f1-75f5-4d0d-9e8e-8bc37a07248d",
                            "strengthScore": 4,
                            "validityScore": 0,
                            "ci": [
                                "CI01"
                            ],
                            "failedCheckDetails": [
                                {
                                    "checkMethod": "data",
                                    "dataCheck": "scenario1_check"
                                },
                                {
                                    "checkMethod": "data",
                                    "dataCheck": "scenario2_check"
                                }
                            ],
                            "checkDetails": [
                                {
                                    "checkMethod": "data",
                                    "dataCheck": "record_check"
                                }
                            ],
                            "ciReasons": [
                                {
                                    "ci": "CI01",
                                    "reason": "Scenario2"
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
    private static final String FAILED_VC_SCENARIO_2_SIGNATURE =
            "bzGrZaM60pussX6G9Jbrlyi15PAJU0J7Z8YhXDjfgfE_7-H0JuZDBde_OGr_pR3jJ72-jTyr44QO0xv0c6LT4Q";

    @Mock private ConfigService mockConfigService;
    @Mock private JWSSigner mockSigner;
    @Mock private SecureTokenHelper mockSecureTokenHelper;

    @Pact(provider = "PassportCriProvider", consumer = "IpvCoreBack")
    public RequestResponsePact validRequestReturnsValidAccessToken(PactDslWithProvider builder) {
        return builder.given("dummyAuthCode is a valid authorization code")
                .given("dummyApiKey is a valid api key")
                .given("dummyPassportComponentId is the passport CRI component ID")
                .given(
                        "Passport CRI uses CORE_BACK_SIGNING_PRIVATE_KEY_JWK to validate core signatures")
                .uponReceiving("Valid auth code")
                .path("/token")
                .method("POST")
                .body(
                        "client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer&code=dummyAuthCode&grant_type=authorization_code&redirect_uri=https%3A%2F%2Fidentity.staging.account.gov.uk%2Fcredential-issuer%2Fcallback%3Fid%3DukPassport&client_assertion="
                        + CLIENT_ASSERTION_HEADER + "." + CLIENT_ASSERTION_BODY + "." + CLIENT_ASSERTION_SIGNATURE)
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
    void fetchAccessToken_whenCalledAgainstPassportCri_retrievesAValidAccessToken(
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
        when(mockSigner.sign(any(), any()))
                .thenReturn(
                        new Base64URL(
                                CLIENT_ASSERTION_SIGNATURE));
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

    @Pact(provider = "PassportCriProvider", consumer = "IpvCoreBack")
    public RequestResponsePact invalidAuthCodeRequestReturns400(PactDslWithProvider builder) {
        return builder.given("dummyInvalidAuthCode is an invalid authorization code")
                .given("dummyApiKey is a valid api key")
                .given("dummyPassportComponentId is the passport CRI component ID")
                .given(
                        "Passport CRI uses CORE_BACK_SIGNING_PRIVATE_KEY_JWK to validate core signatures")
                .uponReceiving("Invalid authorization code")
                .path("/token")
                .method("POST")
                .body(
                        "client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer&code=dummyInvalidAuthCode&grant_type=authorization_code&redirect_uri=https%3A%2F%2Fidentity.staging.account.gov.uk%2Fcredential-issuer%2Fcallback%3Fid%3DukPassport&client_assertion="
                                + CLIENT_ASSERTION_HEADER + "." + CLIENT_ASSERTION_BODY + "." + CLIENT_ASSERTION_SIGNATURE)
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
    void fetchAccessToken_whenCalledAgainstPassportCriWithInvalidAuthCode_throwsAnException(
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
        when(mockSigner.sign(any(), any()))
                .thenReturn(
                        new Base64URL(
                                CLIENT_ASSERTION_SIGNATURE));
        when(mockSigner.supportedJWSAlgorithms()).thenReturn(Set.of(JWSAlgorithm.ES256));
        when(mockSecureTokenHelper.generate())
                .thenReturn("ScnF4dGXthZYXS_5k85ObEoSU04W-H3qa_p6npv2ZUY");

        // We need to generate a fixed request, so we set the secure token and expiry to
        // constant
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
        assertEquals("Invalid token request", exception.getErrorResponse().getMessage());
        assertEquals(400, exception.getHttpStatusCode());
    }

    @Pact(provider = "PassportCriProvider", consumer = "IpvCoreBack")
    public RequestResponsePact validRequestReturnsValidCredential(PactDslWithProvider builder)
            throws Exception {
        return builder.given("dummyApiKey is a valid api key")
                .given("dummyAccessToken is a valid access token")
                .given("test-subject is a valid subject")
                .given("dummyPassportComponentId is a valid issuer")
                .given("VC givenName is Mary")
                .given("VC familyName is Watson")
                .given("VC birthDate is 1932-02-25")
                .given("VC passport documentNumber is 824159121")
                .given("VC passport expiryDate is 2030-01-01")
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
    @PactTestFor(pactMethod = "validRequestReturnsValidCredential")
    void fetchVerifiableCredential_whenCalledAgainstPassportCri_retrievesAValidVc(
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

                                JsonNode nameParts =
                                        credentialSubject.get("name").get(0).get("nameParts");
                                JsonNode birthDateNode = credentialSubject.get("birthDate").get(0);
                                JsonNode passportNode = credentialSubject.get("passport").get(0);

                                assertEquals("GivenName", nameParts.get(0).get("type").asText());
                                assertEquals("FamilyName", nameParts.get(1).get("type").asText());
                                assertEquals("Mary", nameParts.get(0).get("value").asText());
                                assertEquals("Watson", nameParts.get(1).get("value").asText());

                                assertEquals("2030-01-01", passportNode.get("expiryDate").asText());
                                assertEquals(
                                        "824159121", passportNode.get("documentNumber").asText());

                                assertEquals("1932-02-25", birthDateNode.get("value").asText());
                            } catch (VerifiableCredentialException
                                     | ParseException
                                     | JsonProcessingException e) {
                                throw new RuntimeException(e);
                            }
                        });
    }

    @Pact(provider = "PassportCriProvider", consumer = "IpvCoreBack")
    public RequestResponsePact validRequestReturnsFailedCredentialWithCi(
            PactDslWithProvider builder) throws Exception {
        return builder.given("dummyApiKey is a valid api key")
                .given("dummyAccessToken is a valid access token")
                .given("test-subject is a valid subject")
                .given("dummyPassportComponentId is a valid issuer")
                .given("VC givenName is Mary")
                .given("VC familyName is Watson")
                .given("VC birthDate is 1932-02-25")
                .given("VC passport documentNumber is 123456789")
                .given("VC passport expiryDate is 2030-12-12")
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
    @PactTestFor(pactMethod = "validRequestReturnsFailedCredentialWithCi")
    void fetchVerifiableCredential_whenCalledAgainstPassportCri_retrievesAValidVcWithACi(
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

                                JsonNode nameParts =
                                        credentialSubject.get("name").get(0).get("nameParts");
                                JsonNode birthDateNode = credentialSubject.get("birthDate").get(0);
                                JsonNode passportNode = credentialSubject.get("passport").get(0);
                                JsonNode evidence = vc.get("evidence").get(0);
                                JsonNode ciNode = evidence.get("ci");

                                // Assert
                                assertEquals("GivenName", nameParts.get(0).get("type").asText());
                                assertEquals("FamilyName", nameParts.get(1).get("type").asText());
                                assertEquals("Mary", nameParts.get(0).get("value").asText());
                                assertEquals("Watson", nameParts.get(1).get("value").asText());
                                assertEquals("D02", ciNode.get(0).asText());

                                assertEquals("2030-01-01", passportNode.get("expiryDate").asText());
                                assertEquals(
                                        "123456789", passportNode.get("documentNumber").asText());

                                assertEquals("1932-02-25", birthDateNode.get("value").asText());
                            } catch (VerifiableCredentialException
                                    | ParseException
                                    | JsonProcessingException e) {
                                throw new RuntimeException(e);
                            }
                        });
    }

    @Pact(provider = "PassportCriProvider", consumer = "IpvCoreBack")
    public RequestResponsePact validRequestReturnsFailedCredentialWithScenario2Ci(
            PactDslWithProvider builder) throws Exception {
        return builder.given("dummyApiKey is a valid api key")
                .given("dummyAccessToken is a valid access token")
                .given("test-subject is a valid subject")
                .given("dummyPassportComponentId is a valid issuer")
                .given("VC givenName is Mary")
                .given("VC familyName is Watson")
                .given("VC birthDate is 1932-02-25")
                .given("VC passport documentNumber is 123456789")
                .given("VC passport expiryDate is 2030-12-12")
                .given("VC is a scenario 2 failure")
                .uponReceiving("Valid credential request for VC with scenario 2 CI")
                .path("/credential")
                .method("POST")
                .headers("x-api-key", PRIVATE_API_KEY, "Authorization", "Bearer dummyAccessToken")
                .willRespondWith()
                .body(
                        new PactJwtIgnoreSignatureBodyBuilder(
                                VALID_VC_HEADER, FAILED_VC_SCENARIO_2_BODY, FAILED_VC_SCENARIO_2_SIGNATURE))
                .status(200)
                .toPact();
    }

    @Test
    @PactTestFor(pactMethod = "validRequestReturnsFailedCredentialWithScenario2Ci")
    void fetchVerifiableCredential_whenCalledAgainstPassportCri_retrievesAValidVcWithAScenario2Ci(
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

                                JsonNode nameParts =
                                        credentialSubject.get("name").get(0).get("nameParts");
                                JsonNode birthDateNode = credentialSubject.get("birthDate").get(0);
                                JsonNode passportNode = credentialSubject.get("passport").get(0);
                                JsonNode evidence = vc.get("evidence").get(0);
                                JsonNode ciNode = evidence.get("ci");

                                // Assert
                                assertEquals("GivenName", nameParts.get(0).get("type").asText());
                                assertEquals("FamilyName", nameParts.get(1).get("type").asText());
                                assertEquals("Mary", nameParts.get(0).get("value").asText());
                                assertEquals("Watson", nameParts.get(1).get("value").asText());
                                assertEquals("CI01", ciNode.get(0).asText());

                                assertEquals("2030-01-01", passportNode.get("expiryDate").asText());
                                assertEquals(
                                        "123456789", passportNode.get("documentNumber").asText());

                                assertEquals("1932-02-25", birthDateNode.get("value").asText());
                            } catch (VerifiableCredentialException
                                     | ParseException
                                     | JsonProcessingException e) {
                                throw new RuntimeException(e);
                            }
                        });
    }

    @Pact(provider = "PassportCriProvider", consumer = "IpvCoreBack")
    public RequestResponsePact invalidAccessTokenReturns403(PactDslWithProvider builder) {
        return builder.given("dummyApiKey is a valid api key")
                .given("dummyInvalidAccessToken is an invalid access token")
                .given("test-subject is a valid subject")
                .given("dummyPassportComponentId is a valid issuer")
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
                .body(
                        newJsonBody(
                                (body) -> {
                                    body.object("oauth_error", (error) -> {
                                        error.stringType("error");
                                        error.stringType("error_description");
                                    });
                                })
                                .build())
                .toPact();
    }

    @Test
    @PactTestFor(pactMethod = "invalidAccessTokenReturns403")
    void
            fetchVerifiableCredential_whenCalledAgainstPassportCriWithInvalidAuthCode_throwsAnException(
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
    private VerifiableCredentialJwtValidator getVerifiableCredentialJwtValidator() {
        return new VerifiableCredentialJwtValidator(
                mockConfigService,
                ((exactMatchClaims, requiredClaims) ->
                        new FixedTimeJWTClaimsVerifier<>(
                                exactMatchClaims,
                                requiredClaims,
                                Date.from(CURRENT_TIME.instant()))));
    }

    @NotNull
    private static CriCallbackRequest getCallbackRequest(
            String authCode, OauthCriConfig credentialIssuerConfig) {
        return new CriCallbackRequest(
                authCode,
                credentialIssuerConfig.getClientId(),
                "dummySessionId",
                "https://identity.staging.account.gov.uk/credential-issuer/callback?id=ukPassport",
                "dummyState",
                null,
                null,
                "dummyIpAddress",
                "dummyFeatureSet");
    }

    private void configureMockConfigService(OauthCriConfig credentialIssuerConfig) {
        ContraIndicatorConfig ciConfig1 = new ContraIndicatorConfig(null, 4, null, null);
        ContraIndicatorConfig ciConfig2 = new ContraIndicatorConfig(null, 4, null, null);
        Map<String, ContraIndicatorConfig> ciConfigMap = new HashMap<>();
        ciConfigMap.put("D02", ciConfig1);
        ciConfigMap.put("CI01", ciConfig2);

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
                .componentId(CRI_COMPONENT_ID)
                .clientCallbackUrl(
                        URI.create(
                                "https://identity.staging.account.gov.uk/credential-issuer/callback?id=ukPassport"))
                .requiresApiKey(true)
                .requiresAdditionalEvidence(false)
                .build();
    }
}
