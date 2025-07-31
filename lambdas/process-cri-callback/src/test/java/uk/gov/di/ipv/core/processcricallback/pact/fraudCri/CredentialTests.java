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
import static uk.gov.di.ipv.core.library.domain.Cri.EXPERIAN_FRAUD;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.EC_PRIVATE_KEY_JWK;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.RSA_ENCRYPTION_PUBLIC_JWK;

@ExtendWith(PactConsumerTestExt.class)
@ExtendWith(MockitoExtension.class)
@PactTestFor(providerName = "FraudVcProvider")
@MockServerConfig(hostInterface = "localhost")
class CredentialTests {
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final String MOCK_LOCK = "2025-07-28T10:14:07.494907165Z";
    private static final String MOCK_PROCESS_RESULT = "/journey/next";

    @Mock private ConfigService mockConfigService;
    @Mock private SignerFactory mockSignerFactory;
    @Mock private SecureTokenHelper mockSecureTokenHelper;

    @Pact(provider = "FraudVcProvider", consumer = "IpvCoreBack")
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
                .uponReceiving(
                        "Valid credential request for identity check VC with successful PEPs check")
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
                        EXPERIAN_FRAUD,
                        CRI_OAUTH_SESSION_ITEM);

        // Assert
        var verifiableCredentialJwtValidator = getVerifiableCredentialValidator();
        verifiableCredentialResponse
                .getVerifiableCredentials()
                .forEach(
                        credential -> {
                            try {
                                var vc =
                                        verifiableCredentialJwtValidator.parseAndValidate(
                                                TEST_USER,
                                                EXPERIAN_FRAUD,
                                                credential,
                                                EC_PRIVATE_KEY_JWK,
                                                TEST_ISSUER,
                                                false);

                                JsonNode credentialSubject =
                                        OBJECT_MAPPER
                                                .readTree(vc.getClaimsSet().toString())
                                                .get("vc")
                                                .get("credentialSubject");

                                JsonNode vcClaim =
                                        OBJECT_MAPPER
                                                .readTree(vc.getClaimsSet().toString())
                                                .get("vc");

                                JsonNode evidence = vcClaim.get("evidence").get(0);

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
                                assertEquals("BA2 5AA", addressNode.get("postalCode").asText());
                                assertEquals("8", addressNode.get("buildingNumber").asText());

                                assertEquals("BATH", addressNode.get("addressLocality").asText());

                                assertEquals("1965-07-08", birthDateNode.get("value").asText());
                            } catch (VerifiableCredentialException | JsonProcessingException e) {
                                throw new RuntimeException(e);
                            }
                        });
    }

    @Pact(provider = "FraudVcProvider", consumer = "IpvCoreBack")
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
                .given("VC evidence failed txn is dummyTxnFailed")
                .given("VC credentialSubject address streetName is HADLEY ROAD")
                .given("VC credentialSubject address buildingName is LE FLAMBE")
                .given("VC credentialSubject address addressType is CURRENT")
                .given("VC credentialSubject address postalCode is BA2 5AA")
                .given("VC credentialSubject address buildingNumber is 8")
                .given("VC credentialSubject address addressLocality is BATH")
                .uponReceiving(
                        "Valid credential request for identity check VC with a failed PEPs check")
                .path("/credential/issue")
                .method("POST")
                .headers("x-api-key", PRIVATE_API_KEY, "Authorization", "Bearer dummyAccessToken")
                .willRespondWith()
                .status(200)
                .body(
                        new PactJwtIgnoreSignatureBodyBuilder(
                                VALID_VC_HEADER,
                                VALID_EXPERIAN_FRAUD_CHECK_FAILED_PEP_BODY,
                                VALID_EXPERIAN_FRAUD_CHECK_FAILED_PEP_SIGNATURE))
                .toPact();
    }

    @Test
    @PactTestFor(
            pactMethod = "validRequestReturnsExperianFraudCheckIssuedCredentialWithoutPepCheck")
    void
            fetchVerifiableCredential_whenCalledAgainstFraudCheckCri_retrievesAValidExperianFraudCheckVc_withoutPepCheck(
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
                        EXPERIAN_FRAUD,
                        CRI_OAUTH_SESSION_ITEM);

        // Assert
        var verifiableCredentialJwtValidator = getVerifiableCredentialValidator();
        verifiableCredentialResponse
                .getVerifiableCredentials()
                .forEach(
                        credential -> {
                            try {
                                var vc =
                                        verifiableCredentialJwtValidator.parseAndValidate(
                                                TEST_USER,
                                                EXPERIAN_FRAUD,
                                                credential,
                                                EC_PRIVATE_KEY_JWK,
                                                TEST_ISSUER,
                                                false);

                                JsonNode credentialSubject =
                                        OBJECT_MAPPER
                                                .readTree(vc.getClaimsSet().toString())
                                                .get("vc")
                                                .get("credentialSubject");

                                JsonNode vcClaim =
                                        OBJECT_MAPPER
                                                .readTree(vc.getClaimsSet().toString())
                                                .get("vc");

                                JsonNode evidence = vcClaim.get("evidence").get(0);

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
                                assertEquals("BA2 5AA", addressNode.get("postalCode").asText());
                                assertEquals("8", addressNode.get("buildingNumber").asText());
                                assertEquals("BATH", addressNode.get("addressLocality").asText());

                                assertEquals("1965-07-08", birthDateNode.get("value").asText());
                            } catch (VerifiableCredentialException | JsonProcessingException e) {
                                throw new RuntimeException(e);
                            }
                        });
    }

    @Pact(provider = "FraudVcProvider", consumer = "IpvCoreBack")
    public RequestResponsePact validRequestReturnsExperianFraudCheckResponseWithCi(
            PactDslWithProvider builder) {
        return builder.given("dummyApiKey is a valid api key")
                .given("dummyAccessToken is a valid access token")
                .given("test-subject is a valid subject")
                .given("dummyFraudComponentId is a valid issuer")
                .given("VC is for Kenneth Decerqueira")
                .given("VC birthDate is 1965-07-08")
                .given("VC evidence identityFraudScore is 1")
                .given("VC has CI of CI1")
                .given("VC evidence txn is dummyTxn")
                .given("VC credentialSubject address streetName is HADLEY ROAD")
                .given("VC credentialSubject address addressType is CURRENT")
                .given("VC credentialSubject address postalCode is BA2 5AA")
                .given("VC credentialSubject address buildingNumber is 8")
                .given("VC credentialSubject address addressLocality is BATH")
                .uponReceiving(
                        "Valid credential request for identity check VC with successful PEPs check and a CI")
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
                        EXPERIAN_FRAUD,
                        CRI_OAUTH_SESSION_ITEM);

        // Assert
        var verifiableCredentialJwtValidator = getVerifiableCredentialValidator();
        verifiableCredentialResponse
                .getVerifiableCredentials()
                .forEach(
                        credential -> {
                            try {
                                var vc =
                                        verifiableCredentialJwtValidator.parseAndValidate(
                                                TEST_USER,
                                                EXPERIAN_FRAUD,
                                                credential,
                                                EC_PRIVATE_KEY_JWK,
                                                TEST_ISSUER,
                                                false);

                                JsonNode credentialSubject =
                                        OBJECT_MAPPER
                                                .readTree(vc.getClaimsSet().toString())
                                                .get("vc")
                                                .get("credentialSubject");

                                JsonNode vcClaim =
                                        OBJECT_MAPPER
                                                .readTree(vc.getClaimsSet().toString())
                                                .get("vc");

                                JsonNode evidence = vcClaim.get("evidence").get(0);

                                JsonNode nameParts =
                                        credentialSubject.get("name").get(0).get("nameParts");
                                JsonNode birthDateNode = credentialSubject.get("birthDate").get(0);
                                JsonNode addressNode = credentialSubject.get("address").get(0);

                                JsonNode ciNode = evidence.get("ci");

                                assertEquals("2", evidence.get("identityFraudScore").asText());
                                assertEquals("CI1", ciNode.get(0).asText());
                                assertEquals("GivenName", nameParts.get(0).get("type").asText());
                                assertEquals("FamilyName", nameParts.get(1).get("type").asText());
                                assertEquals("Kenneth", nameParts.get(0).get("value").asText());
                                assertEquals("Decerqueira", nameParts.get(1).get("value").asText());

                                assertEquals("HADLEY ROAD", addressNode.get("streetName").asText());
                                assertEquals("BA2 5AA", addressNode.get("postalCode").asText());
                                assertEquals("8", addressNode.get("buildingNumber").asText());

                                assertEquals("BATH", addressNode.get("addressLocality").asText());

                                assertEquals("1965-07-08", birthDateNode.get("value").asText());
                            } catch (VerifiableCredentialException | JsonProcessingException e) {
                                throw new RuntimeException(e);
                            }
                        });
    }

    @Pact(provider = "FraudVcProvider", consumer = "IpvCoreBack")
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
                        mockConfigService, mockSignerFactory, mockSecureTokenHelper, CURRENT_TIME);

        // Act
        CriApiException exception =
                assertThrows(
                        CriApiException.class,
                        () ->
                                underTest.fetchVerifiableCredential(
                                        new BearerAccessToken("dummyInvalidAccessToken"),
                                        EXPERIAN_FRAUD,
                                        CRI_OAUTH_SESSION_ITEM));

        // Assert
        assertThat(
                exception.getErrorResponse(),
                is(ErrorResponse.FAILED_TO_GET_CREDENTIAL_FROM_ISSUER));
        assertThat(exception.getHttpStatusCode(), is(HTTPResponse.SC_SERVER_ERROR));
    }

    @NotNull
    private VerifiableCredentialValidator getVerifiableCredentialValidator() {
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
        Map<String, ContraIndicatorConfig> ciConfigMap = new HashMap<>();
        ciConfigMap.put("CI1", ciConfig1);

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
                        new URI("http://localhost:" + mockServer.getPort() + "/credential/issue"))
                .authorizeUrl(new URI("http://localhost:" + mockServer.getPort() + "/authorize"))
                .clientId(IPV_CORE_CLIENT_ID)
                .signingKey(EC_PRIVATE_KEY_JWK)
                .encryptionKey(RSA_ENCRYPTION_PUBLIC_JWK)
                .componentId(TEST_ISSUER)
                .clientCallbackUrl(
                        URI.create(
                                "https://identity.staging.account.gov.uk/credential-issuer/callback?id=fraud"))
                .requiresApiKey(true)
                .requiresAdditionalEvidence(false)
                .build();
    }

    private static final String TEST_USER = "test-subject";
    private static final String TEST_ISSUER = "dummyFraudComponentId";
    private static final String IPV_CORE_CLIENT_ID = "ipv-core";
    private static final String PRIVATE_API_KEY = "dummyApiKey";
    private static final Clock CURRENT_TIME =
            Clock.fixed(Instant.parse("2099-01-01T00:00:00.00Z"), ZoneOffset.UTC);
    public static final CriOAuthSessionItem CRI_OAUTH_SESSION_ITEM =
            new CriOAuthSessionItem(
                    "dummySessionId",
                    "dummyOAuthSessionId",
                    EXPERIAN_FRAUD.getId(),
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
    private static final String VALID_EXPERIAN_FRAUD_CHECK_VC_BODY =
            """
            {
              "iss": "dummyFraudComponentId",
              "sub": "test-subject",
              "nbf": 4070908800,
              "vc": {
                "type": [
                  "VerifiableCredential",
                  "IdentityCheckCredential"
                ],
                "credentialSubject": {
                  "address": [
                    {
                      "buildingNumber": "8",
                      "buildingName": "LE FLAMBE",
                      "streetName": "HADLEY ROAD",
                      "addressLocality": "BATH",
                      "postalCode": "BA2 5AA",
                      "addressCountry": "GB"
                    }
                  ],
                  "birthDate": [
                    {
                      "value": "1965-07-08"
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
                  ]
                },
                "evidence": [
                  {
                    "type": "IdentityCheck",
                    "txn": "dummyTxn",
                    "identityFraudScore": 2,
                    "ci": [],
                    "activityHistoryScore": 1,
                    "checkDetails": [
                      {
                        "checkMethod": "data",
                        "fraudCheck": "applicable_authoritative_source"
                      },
                      {
                        "checkMethod": "data",
                        "fraudCheck": "available_authoritative_source"
                      },
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
                        "txn": "dummyTxn",
                        "checkMethod": "data",
                        "fraudCheck": "impersonation_risk_check"
                      },
                      {
                        "checkMethod": "data",
                        "activityFrom": "2013-12-01",
                        "identityCheckPolicy": "none"
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
    private static final String VALID_EXPERIAN_FRAUD_CHECK_VC_SIGNATURE =
            "CpyzOMgJH0rDzzl-NCy2PXj9fCyCJD5zEGMkejcsfm-TDtkR4Oy4veXV_HR5JGaSVpMMj6UJ05NutcuSQwML9Q"; // pragma: allowlist secret

    private static final String FAILED_EXPERIAN_FRAUD_CHECK_VC_BODY =
            """
            {
              "iss": "dummyFraudComponentId",
              "sub": "test-subject",
              "nbf": 4070908800,
              "vc": {
                "type": [
                  "VerifiableCredential",
                  "IdentityCheckCredential"
                ],
                "credentialSubject": {
                  "address": [
                    {
                      "buildingNumber": "8",
                      "buildingName": "LE FLAMBE",
                      "streetName": "HADLEY ROAD",
                      "addressLocality": "BATH",
                      "postalCode": "BA2 5AA",
                      "addressCountry": "GB"
                    }
                  ],
                  "birthDate": [
                    {
                      "value": "1965-07-08"
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
                  ]
                },
                "evidence": [
                  {
                    "type": "IdentityCheck",
                    "txn": "dummyTxn",
                    "identityFraudScore": 2,
                    "ci": [
                      "CI1"
                    ],
                    "activityHistoryScore": 1,
                    "checkDetails": [
                      {
                        "checkMethod": "data",
                        "fraudCheck": "applicable_authoritative_source"
                      },
                      {
                        "checkMethod": "data",
                        "fraudCheck": "available_authoritative_source"
                      },
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
                        "txn": "dummyTxn",
                        "checkMethod": "data",
                        "fraudCheck": "impersonation_risk_check"
                      },
                      {
                        "checkMethod": "data",
                        "activityFrom": "2013-12-01",
                        "identityCheckPolicy": "none"
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
    private static final String FAILED_EXPERIAN_FRAUD_CHECK_VC_SIGNATURE =
            "KhDmliwU2182R-zmUZdm-TccBMrJXOsx1f_-pV_YKYUBr16CWPVpZffwlMr2zOTrzpO_8u_mdCuYm1VmtXFc_A"; // pragma: allowlist secret

    private static final String VALID_EXPERIAN_FRAUD_CHECK_FAILED_PEP_BODY =
            """
            {
              "iss": "dummyFraudComponentId",
              "sub": "test-subject",
              "nbf": 4070908800,
              "vc": {
                "type": [
                  "VerifiableCredential",
                  "IdentityCheckCredential"
                ],
                "credentialSubject": {
                  "address": [
                    {
                      "buildingNumber": "8",
                      "buildingName": "LE FLAMBE",
                      "streetName": "HADLEY ROAD",
                      "addressLocality": "BATH",
                      "postalCode": "BA2 5AA",
                      "addressCountry": "GB"
                    }
                  ],
                  "birthDate": [
                    {
                      "value": "1965-07-08"
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
                  ]
                },
                "evidence": [
                  {
                    "type": "IdentityCheck",
                    "txn": "dummyTxn",
                    "identityFraudScore": 1,
                    "ci": [],
                    "activityHistoryScore": 1,
                    "checkDetails": [
                      {
                        "checkMethod": "data",
                        "fraudCheck": "applicable_authoritative_source"
                      },
                      {
                        "checkMethod": "data",
                        "fraudCheck": "available_authoritative_source"
                      },
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
                        "activityFrom": "2013-12-01",
                        "identityCheckPolicy": "none"
                      }
                    ],
                    "failedCheckDetails": [
                      {
                        "txn": "dummyTxnFailed",
                        "checkMethod": "data",
                        "fraudCheck": "impersonation_risk_check"
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
    private static final String VALID_EXPERIAN_FRAUD_CHECK_FAILED_PEP_SIGNATURE =
            "bCHcCM5hoozwTUvVr-6kf623R6gYkbXZL69CD7qH2lGuNf2Ih-dHzFKSUmNFivbD5CE5AOJ0dgpClqvN_X_IbQ"; // pragma: allowlist secret
}
