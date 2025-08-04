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
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.criapiservice.CriApiService;
import uk.gov.di.ipv.core.library.criapiservice.exception.CriApiException;
import uk.gov.di.ipv.core.library.domain.ContraIndicatorConfig;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.dto.OauthCriConfig;
import uk.gov.di.ipv.core.library.exceptions.VerifiableCredentialException;
import uk.gov.di.ipv.core.library.helpers.FixedTimeJWTClaimsVerifier;
import uk.gov.di.ipv.core.library.helpers.SecureTokenHelper;
import uk.gov.di.ipv.core.library.persistence.item.CriOAuthSessionItem;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.signing.CoreSigner;
import uk.gov.di.ipv.core.library.signing.SignerFactory;
import uk.gov.di.ipv.core.library.testhelpers.pact.PactJwtIgnoreSignatureBodyBuilder;
import uk.gov.di.ipv.core.library.verifiablecredential.validator.VerifiableCredentialValidator;

import java.net.URI;
import java.net.URISyntaxException;
import java.sql.Date;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.HashMap;
import java.util.Map;

import static au.com.dius.pact.consumer.dsl.LambdaDsl.newJsonBody;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.domain.Cri.PASSPORT;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.EC_PRIVATE_KEY_JWK;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.RSA_ENCRYPTION_PUBLIC_JWK;

@ExtendWith(PactConsumerTestExt.class)
@ExtendWith(MockitoExtension.class)
@PactTestFor(providerName = "PassportVcProvider")
@MockServerConfig(hostInterface = "localhost")
class CredentialTests {
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final String MOCK_LOCK = "2025-07-28T10:14:07.494907165Z";
    private static final String MOCK_PROCESS_RESULT = "/journey/next";

    @Mock private ConfigService mockConfigService;
    @Mock private SignerFactory mockSignerFactory;
    @Mock private CoreSigner mockSigner;
    @Mock private SecureTokenHelper mockSecureTokenHelper;

    @Pact(provider = "PassportVcProvider", consumer = "IpvCoreBack")
    public RequestResponsePact validRequestReturnsValidCredential(PactDslWithProvider builder) {
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
                .path("/issue/credential")
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
            MockServer mockServer)
            throws URISyntaxException, CriApiException, JsonProcessingException {
        // Arrange
        var credentialIssuerConfig = getMockCredentialIssuerConfig(mockServer);
        configureMockConfigService(credentialIssuerConfig);

        // We need to generate a fixed request, so we set the secure token and expiry to constant
        // values.
        var underTest =
                new CriApiService(
                        mockConfigService, mockSignerFactory, mockSecureTokenHelper, CURRENT_TIME);

        // Act
        var verifiableCredentialResponse =
                underTest.fetchVerifiableCredential(
                        new BearerAccessToken("dummyAccessToken"),
                        PASSPORT,
                        CRI_OAUTH_SESSION_ITEM);

        // Assert
        var verifiableCredentialJwtValidator = getVerifiableCredentialJwtValidator();
        verifiableCredentialResponse
                .getVerifiableCredentials()
                .forEach(
                        credential -> {
                            try {
                                var vc =
                                        verifiableCredentialJwtValidator.parseAndValidate(
                                                TEST_USER,
                                                PASSPORT,
                                                credential,
                                                EC_PRIVATE_KEY_JWK,
                                                TEST_ISSUER,
                                                false);

                                JsonNode credentialSubject =
                                        OBJECT_MAPPER
                                                .readTree(vc.getClaimsSet().toString())
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
                            } catch (VerifiableCredentialException | JsonProcessingException e) {
                                throw new RuntimeException(e);
                            }
                        });
    }

    @Pact(provider = "PassportVcProvider", consumer = "IpvCoreBack")
    public RequestResponsePact validRequestReturnsFailedCredentialWithCi(
            PactDslWithProvider builder) {
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
                .path("/issue/credential")
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
            MockServer mockServer)
            throws URISyntaxException, CriApiException, JsonProcessingException {
        // Arrange
        var credentialIssuerConfig = getMockCredentialIssuerConfig(mockServer);
        configureMockConfigService(credentialIssuerConfig);

        // We need to generate a fixed request, so we set the secure token and expiry to constant
        // values.
        var underTest =
                new CriApiService(
                        mockConfigService, mockSignerFactory, mockSecureTokenHelper, CURRENT_TIME);

        // Act
        var verifiableCredentialResponse =
                underTest.fetchVerifiableCredential(
                        new BearerAccessToken("dummyAccessToken"),
                        PASSPORT,
                        CRI_OAUTH_SESSION_ITEM);

        // Assert
        var verifiableCredentialJwtValidator = getVerifiableCredentialJwtValidator();
        verifiableCredentialResponse
                .getVerifiableCredentials()
                .forEach(
                        credential -> {
                            try {
                                var vc =
                                        verifiableCredentialJwtValidator.parseAndValidate(
                                                TEST_USER,
                                                PASSPORT,
                                                credential,
                                                EC_PRIVATE_KEY_JWK,
                                                TEST_ISSUER,
                                                false);

                                JsonNode vcClaim =
                                        OBJECT_MAPPER
                                                .readTree(vc.getClaimsSet().toString())
                                                .get("vc");

                                JsonNode credentialSubject = vcClaim.get("credentialSubject");

                                JsonNode nameParts =
                                        credentialSubject.get("name").get(0).get("nameParts");
                                JsonNode birthDateNode = credentialSubject.get("birthDate").get(0);
                                JsonNode passportNode = credentialSubject.get("passport").get(0);
                                JsonNode evidence = vcClaim.get("evidence").get(0);
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
                            } catch (VerifiableCredentialException | JsonProcessingException e) {
                                throw new RuntimeException(e);
                            }
                        });
    }

    @Pact(provider = "PassportVcProvider", consumer = "IpvCoreBack")
    public RequestResponsePact validRequestReturnsFailedCredentialWithScenario2Ci(
            PactDslWithProvider builder) {
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
                .path("/issue/credential")
                .method("POST")
                .headers("x-api-key", PRIVATE_API_KEY, "Authorization", "Bearer dummyAccessToken")
                .willRespondWith()
                .body(
                        new PactJwtIgnoreSignatureBodyBuilder(
                                VALID_VC_HEADER,
                                FAILED_VC_SCENARIO_2_BODY,
                                FAILED_VC_SCENARIO_2_SIGNATURE))
                .status(200)
                .toPact();
    }

    @Test
    @PactTestFor(pactMethod = "validRequestReturnsFailedCredentialWithScenario2Ci")
    void fetchVerifiableCredential_whenCalledAgainstPassportCri_retrievesAValidVcWithAScenario2Ci(
            MockServer mockServer)
            throws URISyntaxException, CriApiException, JsonProcessingException {
        // Arrange
        var credentialIssuerConfig = getMockCredentialIssuerConfig(mockServer);
        configureMockConfigService(credentialIssuerConfig);

        // We need to generate a fixed request, so we set the secure token and expiry to constant
        // values.
        var underTest =
                new CriApiService(
                        mockConfigService, mockSignerFactory, mockSecureTokenHelper, CURRENT_TIME);

        // Act
        var verifiableCredentialResponse =
                underTest.fetchVerifiableCredential(
                        new BearerAccessToken("dummyAccessToken"),
                        PASSPORT,
                        CRI_OAUTH_SESSION_ITEM);

        // Assert
        var verifiableCredentialJwtValidator = getVerifiableCredentialJwtValidator();
        verifiableCredentialResponse
                .getVerifiableCredentials()
                .forEach(
                        credential -> {
                            try {
                                var vc =
                                        verifiableCredentialJwtValidator.parseAndValidate(
                                                TEST_USER,
                                                PASSPORT,
                                                credential,
                                                EC_PRIVATE_KEY_JWK,
                                                TEST_ISSUER,
                                                false);

                                JsonNode vcClaim =
                                        OBJECT_MAPPER
                                                .readTree(vc.getClaimsSet().toString())
                                                .get("vc");

                                JsonNode credentialSubject = vcClaim.get("credentialSubject");

                                JsonNode nameParts =
                                        credentialSubject.get("name").get(0).get("nameParts");
                                JsonNode birthDateNode = credentialSubject.get("birthDate").get(0);
                                JsonNode passportNode = credentialSubject.get("passport").get(0);
                                JsonNode evidence = vcClaim.get("evidence").get(0);
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
                            } catch (VerifiableCredentialException | JsonProcessingException e) {
                                throw new RuntimeException(e);
                            }
                        });
    }

    @Pact(provider = "PassportVcProvider", consumer = "IpvCoreBack")
    public RequestResponsePact invalidAccessTokenReturns403(PactDslWithProvider builder) {
        return builder.given("dummyApiKey is a valid api key")
                .given("dummyInvalidAccessToken is an invalid access token")
                .given("test-subject is a valid subject")
                .given("dummyPassportComponentId is a valid issuer")
                .uponReceiving("Invalid credential request due to invalid access token")
                .path("/issue/credential")
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
                                        body -> {
                                            body.object(
                                                    "oauth_error",
                                                    error -> {
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
                    MockServer mockServer) throws URISyntaxException {
        // Arrange
        var credentialIssuerConfig = getMockCredentialIssuerConfig(mockServer);
        configureMockConfigService(credentialIssuerConfig);

        // We need to generate a fixed request, so we set the secure token and expiry to constant
        // values.
        var underTest =
                new CriApiService(
                        mockConfigService, mockSignerFactory, mockSecureTokenHelper, CURRENT_TIME);

        // Act
        CriApiException exception =
                assertThrows(
                        CriApiException.class,
                        () ->
                                underTest.fetchVerifiableCredential(
                                        new BearerAccessToken("dummyInvalidAccessToken"),
                                        PASSPORT,
                                        CRI_OAUTH_SESSION_ITEM));

        // Assert
        assertThat(
                exception.getErrorResponse(),
                is(ErrorResponse.FAILED_TO_GET_CREDENTIAL_FROM_ISSUER));
        assertThat(exception.getHttpStatusCode(), is(HTTPResponse.SC_SERVER_ERROR));
    }

    @NotNull
    private VerifiableCredentialValidator getVerifiableCredentialJwtValidator() {
        return new VerifiableCredentialValidator(
                mockConfigService,
                ((exactMatchClaims, requiredClaims) ->
                        new FixedTimeJWTClaimsVerifier<>(
                                exactMatchClaims,
                                requiredClaims,
                                Date.from(CURRENT_TIME.instant()))));
    }

    private void configureMockConfigService(OauthCriConfig credentialIssuerConfig) {
        ContraIndicatorConfig ciConfig1 = new ContraIndicatorConfig(null, 4, null, null);
        ContraIndicatorConfig ciConfig2 = new ContraIndicatorConfig(null, 4, null, null);
        Map<String, ContraIndicatorConfig> ciConfigMap = new HashMap<>();
        ciConfigMap.put("D02", ciConfig1);
        ciConfigMap.put("CI01", ciConfig2);

        when(mockConfigService.getOauthCriConfig(any())).thenReturn(credentialIssuerConfig);
        when(mockConfigService.getSecret(any(), any(String[].class))).thenReturn(PRIVATE_API_KEY);
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
                        new URI("http://localhost:" + mockServer.getPort() + "/issue/credential"))
                .authorizeUrl(new URI("http://localhost:" + mockServer.getPort() + "/authorize"))
                .clientId(IPV_CORE_CLIENT_ID)
                .signingKey(EC_PRIVATE_KEY_JWK)
                .encryptionKey(RSA_ENCRYPTION_PUBLIC_JWK)
                .componentId(CRI_COMPONENT_ID)
                .clientCallbackUrl(
                        URI.create(
                                "https://identity.staging.account.gov.uk/credential-issuer/callback?id=ukPassport"))
                .requiresApiKey(true)
                .requiresAdditionalEvidence(false)
                .build();
    }

    private static final String TEST_USER = "test-subject";
    private static final String TEST_ISSUER = "dummyPassportComponentId";
    private static final String IPV_CORE_CLIENT_ID = "ipv-core";
    private static final String PRIVATE_API_KEY = "dummyApiKey";
    public static final String CRI_COMPONENT_ID = "dummyPassportComponentId";
    private static final Clock CURRENT_TIME =
            Clock.fixed(Instant.parse("2099-01-01T00:00:00.00Z"), ZoneOffset.UTC);
    public static final CriOAuthSessionItem CRI_OAUTH_SESSION_ITEM =
            new CriOAuthSessionItem(
                    "dummySessionId",
                    "dummyOAuthSessionId",
                    PASSPORT.getId(),
                    "dummyConnection",
                    MOCK_LOCK,
                    MOCK_PROCESS_RESULT,
                    900);

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
                },
                "jti": "urn:uuid:b07cc7e3-a2dc-4b17-9826-6907fcf4059a"
            }
            """;
    // If we generate the signature in code it will be different each time, so we need to generate a
    // valid signature (using https://jwt.io works well) and record it here so the PACT file doesn't
    // change each time we run the tests.
    private static final String VALID_VC_SIGNATURE =
            "ZmeS-B5HQkQBEOnRogwGVuYORA28YiriPbdeKeGUtwVJ4bmvOAZD5ePNVOKO6788N8TAuYCC1uofV0J1gr_e9g"; // pragma: allowlist secret

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
                },
                "jti": "urn:uuid:b07cc7e3-a2dc-4b17-9826-6907fcf4059a"
            }
            """;
    // If we generate the signature in code it will be different each time, so we need to generate a
    // valid signature (using https://jwt.io works well) and record it here so the PACT file doesn't
    // change each time we run the tests.
    private static final String FAILED_VC_SIGNATURE =
            "BqDbzSgjr-kMUEMgtaMJ1Cr3zypulFXwXL6wPsz8rvlqL32Y_I_KyEnyf1oKnSuQAfEQIOtgHazi1kMO5ZElNg"; // pragma: allowlist secret

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
                            "checkDetails": [
                                {
                                    "checkMethod": "data",
                                    "dataCheck": "record_check"
                                }
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
                            "ciReasons": [
                                {
                                    "ci": "CI01",
                                    "reason": "Scenario2"
                                }
                            ]
                        }
                    ]
                },
                "jti": "urn:uuid:b07cc7e3-a2dc-4b17-9826-6907fcf4059a"
            }
            """;
    // If we generate the signature in code it will be different each time, so we need to generate a
    // valid signature (using https://jwt.io works well) and record it here so the PACT file doesn't
    // change each time we run the tests.
    private static final String FAILED_VC_SCENARIO_2_SIGNATURE =
            "Nhtx_3xy_cjZCCA_rpdVTSg6WjutpPdZ0_BxBQrAx_hAy6Wr86H22iKL4O-B0dQ4z9-hzJOq3Y90IKp5pQNqLg"; // pragma: allowlist secret
}
