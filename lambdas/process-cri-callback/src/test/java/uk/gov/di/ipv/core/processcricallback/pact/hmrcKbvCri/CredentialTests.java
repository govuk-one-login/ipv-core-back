package uk.gov.di.ipv.core.processcricallback.pact.hmrcKbvCri;

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

import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.domain.Cri.HMRC_KBV;
import static uk.gov.di.ipv.core.library.domain.Cri.HMRC_MIGRATION;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.EC_PRIVATE_KEY_JWK;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.RSA_ENCRYPTION_PUBLIC_JWK;

@ExtendWith(PactConsumerTestExt.class)
@ExtendWith(MockitoExtension.class)
@PactTestFor(providerName = "HmrcKbvCriVcProvider")
@MockServerConfig(hostInterface = "localhost")
class CredentialTests {
    @Mock private ConfigService mockConfigService;
    @Mock private SignerFactory mockSignerFactory;
    @Mock private SecureTokenHelper mockSecureTokenHelper;

    @Pact(provider = "HmrcKbvCriVcProvider", consumer = "IpvCoreBack")
    public RequestResponsePact validRequestReturnsIssuedCredential(PactDslWithProvider builder) {

        return builder.given("dummyApiKey is a valid api key")
                .given("dummyAccessToken is a valid access token")
                .given("test-subject is a valid subject")
                .given("dummyHmrcKbvComponentId is a valid issuer")
                .given("VC givenName is Mary")
                .given("VC familyName is Watson")
                .given("VC birthDate is 1932-02-25")
                .given("VC evidence verificationScore is 2")
                .given("VC evidence txn is dummyTxn")
                .given("VC personalNumber is AA000003D")
                .given("VC evidence checkDetails are free_text, multiple_choice, multiple_choice")
                .given("VC jti is test-jti")
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
    void fetchVerifiableCredential_whenCalledAgainstHmrcKbvCri_retrievesAValidVc(
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
                        HMRC_KBV,
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
                                                HMRC_MIGRATION,
                                                credential,
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
                                JsonNode socialSecurityRecordNode =
                                        credentialSubject.get("socialSecurityRecord").get(0);
                                assertEquals("GivenName", nameParts.get(0).get("type").asText());
                                assertEquals("FamilyName", nameParts.get(1).get("type").asText());
                                assertEquals("Mary", nameParts.get(0).get("value").asText());
                                assertEquals("Watson", nameParts.get(1).get("value").asText());
                                assertEquals(
                                        "AA000003D",
                                        socialSecurityRecordNode.get("personalNumber").asText());
                            } catch (VerifiableCredentialException | JsonProcessingException e) {
                                throw new RuntimeException(e);
                            }
                        });
    }

    @Pact(provider = "HmrcKbvCriVcProvider", consumer = "IpvCoreBack")
    public RequestResponsePact validRequestReturnsIssuedCredentialWithFailedAnswer(
            PactDslWithProvider builder) {
        return builder.given("dummyApiKey is a valid api key")
                .given("dummyAccessToken is a valid access token")
                .given("test-subject is a valid subject")
                .given("dummyHmrcKbvComponentId is a valid issuer")
                .given("VC givenName is Mary")
                .given("VC familyName is Watson")
                .given("VC birthDate is 1932-02-25")
                .given("VC evidence verificationScore is 2")
                .given("VC evidence txn is dummyTxn")
                .given("VC personalNumber is AA000003D")
                .given("VC evidence checkDetails are free_text, free_text, multiple_choice")
                .given("VC evidence failedCheckDetails is multiple_choice")
                .given("VC jti is test-jti")
                .uponReceiving("Valid credential request for VC")
                .path("/credential")
                .method("POST")
                .headers("x-api-key", PRIVATE_API_KEY, "Authorization", "Bearer dummyAccessToken")
                .willRespondWith()
                .status(200)
                .body(
                        new PactJwtIgnoreSignatureBodyBuilder(
                                VALID_VC_HEADER,
                                VALID_VC_BODY_WITH_WRONG_ANSWER,
                                VALID_VC_WRONG_ANSWER_SIGNATURE))
                .toPact();
    }

    @Test
    @PactTestFor(pactMethod = "validRequestReturnsIssuedCredentialWithFailedAnswer")
    void fetchVerifiableCredential_whenCalledAgainstHmrcKbvCri_retrievesAValidVcWithFailedAnswer(
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
                        HMRC_KBV,
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
                                                HMRC_MIGRATION,
                                                credential,
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
                                JsonNode socialSecurityRecordNode =
                                        credentialSubject.get("socialSecurityRecord").get(0);
                                JsonNode vcClaim =
                                        objectMapper
                                                .readTree(vc.getClaimsSet().toString())
                                                .get("vc");
                                JsonNode evidence = vcClaim.get("evidence").get(0);
                                JsonNode failedCheckDetailsNode =
                                        evidence.get("failedCheckDetails");

                                assertEquals("GivenName", nameParts.get(0).get("type").asText());
                                assertEquals("FamilyName", nameParts.get(1).get("type").asText());
                                assertEquals("Mary", nameParts.get(0).get("value").asText());
                                assertEquals("Watson", nameParts.get(1).get("value").asText());
                                assertEquals(
                                        "multiple_choice",
                                        failedCheckDetailsNode
                                                .get(0)
                                                .get("kbvResponseMode")
                                                .asText());
                                assertEquals(
                                        2, failedCheckDetailsNode.get(0).get("kbvQuality").asInt());
                                assertEquals(
                                        "kbv",
                                        failedCheckDetailsNode.get(0).get("checkMethod").asText());
                                assertEquals(
                                        "AA000003D",
                                        socialSecurityRecordNode.get("personalNumber").asText());
                            } catch (VerifiableCredentialException | JsonProcessingException e) {
                                throw new RuntimeException(e);
                            }
                        });
    }

    @Pact(provider = "HmrcKbvCriVcProvider", consumer = "IpvCoreBack")
    public RequestResponsePact invalidAccessTokenReturns401(PactDslWithProvider builder) {
        return builder.given("dummyApiKey is a valid api key")
                .given("dummyInvalidAccessToken is an invalid access token")
                .given("test-subject is a valid subject")
                .given("dummyHmrcKbvComponentId is a valid issuer")
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
    void fetchVerifiableCredential_whenCalledAgainstHmrcKbvCriWithInvalidAuthCode_throwsAnException(
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
                                        HMRC_KBV,
                                        CRI_OAUTH_SESSION_ITEM));

        // Assert
        assertThat(
                exception.getErrorResponse(),
                is(ErrorResponse.FAILED_TO_GET_CREDENTIAL_FROM_ISSUER));
        assertThat(exception.getHttpStatusCode(), is(HTTPResponse.SC_SERVER_ERROR));
    }

    @Pact(provider = "HmrcKbvCriVcProvider", consumer = "IpvCoreBack")
    public RequestResponsePact validRequestReturnsIssuedCredentialWithCi(
            PactDslWithProvider builder) {
        return builder.given("dummyApiKey is a valid api key")
                .given("dummyAccessToken is a valid access token")
                .given("test-subject is a valid subject")
                .given("dummyHmrcKbvComponentId is a valid issuer")
                .given("VC givenName is Mary")
                .given("VC familyName is Watson")
                .given("VC birthDate is 1932-02-25")
                .given("VC evidence verificationScore is 0")
                .given("VC evidence txn is dummyTxn")
                .given("VC personalNumber is AA000003D")
                .given("VC evidence checkDetails is free_text")
                .given("VC evidence failedCheckDetails are free_text, multiple_choice")
                .given("VC jti is test-jti")
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
    void fetchVerifiableCredential_whenCalledAgainstHmrcKbvCri_retrievesAValidVcWithACi(
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
                        HMRC_KBV,
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
                                                HMRC_MIGRATION,
                                                credential,
                                                EC_PRIVATE_KEY_JWK,
                                                TEST_ISSUER,
                                                false);

                                JsonNode vcClaim =
                                        objectMapper
                                                .readTree(vc.getClaimsSet().toString())
                                                .get("vc");

                                JsonNode credentialSubject = vcClaim.get("credentialSubject");

                                JsonNode nameParts =
                                        credentialSubject.get("name").get(0).get("nameParts");
                                JsonNode evidence = vcClaim.get("evidence").get(0);
                                JsonNode socialSecurityRecordNode =
                                        credentialSubject.get("socialSecurityRecord").get(0);
                                JsonNode ciNode = evidence.get("ci");
                                JsonNode failedCheckDetailsNode =
                                        evidence.get("failedCheckDetails");

                                // Assert
                                assertEquals("GivenName", nameParts.get(0).get("type").asText());
                                assertEquals("FamilyName", nameParts.get(1).get("type").asText());
                                assertEquals("Mary", nameParts.get(0).get("value").asText());
                                assertEquals("Watson", nameParts.get(1).get("value").asText());
                                assertEquals(
                                        "AA000003D",
                                        socialSecurityRecordNode.get("personalNumber").asText());
                                assertEquals("V03", ciNode.get(0).asText());
                                assertEquals(
                                        "free_text",
                                        failedCheckDetailsNode
                                                .get(0)
                                                .get("kbvResponseMode")
                                                .asText());
                                assertEquals(
                                        3, failedCheckDetailsNode.get(0).get("kbvQuality").asInt());
                                assertEquals(
                                        "kbv",
                                        failedCheckDetailsNode.get(0).get("checkMethod").asText());
                            } catch (VerifiableCredentialException | JsonProcessingException e) {
                                throw new RuntimeException(e);
                            }
                        });
    }

    private void configureMockConfigService(OauthCriConfig credentialIssuerConfig) {
        ContraIndicatorConfig ciConfig1 = new ContraIndicatorConfig(null, 4, null, null);
        Map<String, ContraIndicatorConfig> ciConfigMap = new HashMap<>();
        ciConfigMap.put("V03", ciConfig1);

        when(mockConfigService.getOauthCriConfig(any())).thenReturn(credentialIssuerConfig);
        when(mockConfigService.getSecret(any(), any(String[].class))).thenReturn(PRIVATE_API_KEY);
        // This mock doesn't get reached in error cases, but it would be messy to explicitly not set
        // it
        Mockito.lenient()
                .when(mockConfigService.getContraIndicatorConfigMap())
                .thenReturn(ciConfigMap);
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
                                "https://identity.staging.account.gov.uk/credential-issuer/callback?id=hmrcKbv"))
                .requiresApiKey(true)
                .requiresAdditionalEvidence(false)
                .build();
    }

    private static final String TEST_USER = "test-subject";
    private static final String TEST_ISSUER = "dummyHmrcKbvComponentId";
    private static final String IPV_CORE_CLIENT_ID = "ipv-core";
    private static final String PRIVATE_API_KEY = "dummyApiKey";
    private static final Clock CURRENT_TIME =
            Clock.fixed(Instant.parse("2099-01-01T00:00:00.00Z"), ZoneOffset.UTC);
    public static final CriOAuthSessionItem CRI_OAUTH_SESSION_ITEM =
            new CriOAuthSessionItem(
                    "dummySessionId",
                    "dummyOAuthSessionId",
                    HMRC_KBV.getId(),
                    "dummyConnection",
                    900);

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

    private static final String VALID_VC_BODY =
            """
            {
              "iss": "dummyHmrcKbvComponentId",
              "sub": "test-subject",
              "nbf": 4070908800,
              "vc": {
                "evidence": [{
                  "checkDetails": [{
                    "kbvResponseMode": "free_text",
                    "kbvQuality": 3,
                    "checkMethod": "kbv"
                  },
                  {
                    "kbvResponseMode": "multiple_choice",
                    "kbvQuality": 3,
                    "checkMethod": "kbv"
                  },
                  {
                    "kbvResponseMode": "multiple_choice",
                    "kbvQuality": 2,
                    "checkMethod": "kbv"
                  }
                  ],
                  "verificationScore": 2,
                  "txn": "dummyTxn",
                  "type": "IdentityCheck"
                }],
                "credentialSubject": {
                  "socialSecurityRecord": [
                    {
                      "personalNumber": "AA000003D"
                    }
                  ],
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
                  ]
                },
                "type": [
                  "VerifiableCredential",
                  "IdentityCheckCredential"
                ],
                "@context": [
                  "https://www.w3.org/2018/credentials/v1",
                  "https://vocab.account.gov.uk/contexts/identity-v1.jsonld"
                ]
              },
              "jti": "test-jti"
            }
            """;
    // If we generate the signature in code it will be different each time, so we need to generate a
    // valid signature (using https://jwt.io works well) and record it here so the PACT file doesn't
    // change each time we run the tests.
    private static final String VALID_VC_SIGNATURE =
            "V_UjPKzCPWi3dMokCPk2TCahyyRU2P3V1ZoGD5-cCdOyq_Hx-1tCSfRC387kw-KSW8sHhxRUlCXY3Nbghwvu9w"; // pragma: allowlist secret

    private static final String VALID_VC_BODY_WITH_WRONG_ANSWER =
            """
            {
              "iss": "dummyHmrcKbvComponentId",
              "sub": "test-subject",
              "nbf": 4070908800,
              "vc": {
                "evidence": [{
                  "checkDetails": [{
                    "kbvResponseMode": "free_text",
                    "kbvQuality": 3,
                    "checkMethod": "kbv"
                  },
                  {
                    "kbvResponseMode": "free_text",
                    "kbvQuality": 2,
                    "checkMethod": "kbv"
                  },
                  {
                    "kbvResponseMode": "multiple_choice",
                    "kbvQuality": 3,
                    "checkMethod": "kbv"
                  }],
                  "failedCheckDetails": [{
                    "kbvResponseMode": "multiple_choice",
                    "kbvQuality": 2,
                    "checkMethod": "kbv"
                  }],
                  "verificationScore": 2,
                  "txn": "dummyTxn",
                  "type": "IdentityCheck"
                }],
                "credentialSubject": {
                  "socialSecurityRecord": [
                    {
                      "personalNumber": "AA000003D"
                    }
                  ],
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
                  ]
                },
                "type": [
                  "VerifiableCredential",
                  "IdentityCheckCredential"
                ],
                "@context": [
                  "https://www.w3.org/2018/credentials/v1",
                  "https://vocab.account.gov.uk/contexts/identity-v1.jsonld"
                ]
              },
              "jti": "test-jti"
            }
            """;
    // If we generate the signature in code it will be different each time, so we need to generate a
    // valid signature (using https://jwt.io works well) and record it here so the PACT file doesn't
    // change each time we run the tests.
    private static final String VALID_VC_WRONG_ANSWER_SIGNATURE =
            "w-RBzC28PrsMJKe-2W_dLOYYlAskkXm4-jmUeThOy33h3ZYoDdJa_0dTcHaLStjL82ryfcYKLjplaQZ0Z1vINA"; // pragma: allowlist secret

    private static final String FAILED_VC_BODY =
            """
            {
              "iss": "dummyHmrcKbvComponentId",
              "sub": "test-subject",
              "nbf": 4070908800,
              "vc": {
                "evidence": [{
                  "checkDetails": [{
                    "kbvResponseMode": "free_text",
                    "kbvQuality": 3,
                    "checkMethod": "kbv"
                  }],
                  "failedCheckDetails": [{
                    "kbvResponseMode": "free_text",
                    "kbvQuality": 3,
                    "checkMethod": "kbv"
                  },
                  {
                    "kbvResponseMode": "multiple_choice",
                    "kbvQuality": 2,
                    "checkMethod": "kbv"
                  }],
                  "ci": ["V03"],
                  "verificationScore": 0,
                  "txn": "dummyTxn",
                  "type": "IdentityCheck"
                }],
                "credentialSubject": {
                  "socialSecurityRecord": [
                    {
                      "personalNumber": "AA000003D"
                    }
                  ],
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
                  ]
                },
                "type": [
                  "VerifiableCredential",
                  "IdentityCheckCredential"
                ],
                "@context": [
                  "https://www.w3.org/2018/credentials/v1",
                  "https://vocab.account.gov.uk/contexts/identity-v1.jsonld"
                ]
              },
              "jti": "test-jti"
            }
            """;
    // If we generate the signature in code it will be different each time, so we need to generate a
    // valid signature (using https://jwt.io works well) and record it here so the PACT file doesn't
    // change each time we run the tests.
    private static final String FAILED_VC_SIGNATURE =
            "Fm6ARQEa45XugCHysgvGvo8HqSbZpVok0q8I708ejTwDUIbf7ya7PvoN4mAT4PR-ZMe1KnZVbFN2lZ_aVw9TRw"; // pragma: allowlist secret
}
