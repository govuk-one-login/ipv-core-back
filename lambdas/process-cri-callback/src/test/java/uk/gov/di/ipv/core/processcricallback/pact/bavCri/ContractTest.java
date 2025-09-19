package uk.gov.di.ipv.core.processcricallback.pact.bavCri;

import au.com.dius.pact.consumer.MockServer;
import au.com.dius.pact.consumer.dsl.PactDslJsonRootValue;
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
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.token.AccessTokenType;
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
import uk.gov.di.ipv.core.library.dto.CriCallbackRequest;
import uk.gov.di.ipv.core.library.dto.OauthCriConfig;
import uk.gov.di.ipv.core.library.exceptions.VerifiableCredentialException;
import uk.gov.di.ipv.core.library.helpers.FixedTimeJWTClaimsVerifier;
import uk.gov.di.ipv.core.library.helpers.SecureTokenHelper;
import uk.gov.di.ipv.core.library.persistence.item.CriOAuthSessionItem;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.signing.CoreSigner;
import uk.gov.di.ipv.core.library.signing.SignerFactory;
import uk.gov.di.ipv.core.library.testhelpers.pact.PactJwtBuilder;
import uk.gov.di.ipv.core.library.verifiablecredential.validator.VerifiableCredentialValidator;

import java.net.URI;
import java.net.URISyntaxException;
import java.sql.Date;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.HashMap;
import java.util.List;
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
import static uk.gov.di.ipv.core.library.domain.Cri.BAV;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.EC_PRIVATE_KEY_JWK;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.RSA_ENCRYPTION_PUBLIC_JWK;

@ExtendWith(PactConsumerTestExt.class)
@ExtendWith(MockitoExtension.class)
@PactTestFor(providerName = "BavCriProvider")
@MockServerConfig(hostInterface = "localhost")
class ContractTest {
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    @Mock private ConfigService mockConfigService;
    @Mock private SignerFactory mockSignerFactory;
    @Mock private CoreSigner mockSigner;
    @Mock private SecureTokenHelper mockSecureTokenHelper;

    @Pact(provider = "BavCriProvider", consumer = "IpvCoreBack")
    public RequestResponsePact validRequestReturnsBavIssuedCredential(PactDslWithProvider builder) {
        return builder.given("dummyApiKey is a valid api key")
                .given(VALID_ACCESS_TOKEN + " is a valid access token")
                .given("test-subject is a valid subject")
                .given(TEST_ISSUER + " is the BAV CRI component ID")
                .given("VC evidence checkDetails identityCheckPolicy is none")
                .given("VC evidence checkDetails checkMethod is data")
                .given("VC evidence validityScore is 2")
                .given("VC evidence strengthScore is 3")
                .given("VC evidence txn is dummyTxn")
                .given("VC evidence credentialSubject contains bankAccount")
                .given("VC bankAccount accountNumber is 12345678")
                .given("VC bankAccount sortCode is 103233")
                .given("VC is for Kenneth Decerqueira")
                .uponReceiving("Valid POST request")
                .path("/userinfo")
                .method("POST")
                .headers(
                        "x-api-key",
                        PRIVATE_API_KEY,
                        "Authorization",
                        "Bearer " + VALID_ACCESS_TOKEN)
                .willRespondWith()
                .status(200)
                .body(
                        newJsonBody(
                                        body -> {
                                            var jwtBuilder =
                                                    new PactJwtBuilder(
                                                            VALID_VC_HEADER,
                                                            VALID_BAV_VC_BODY,
                                                            VALID_BAV_VC_SIGNATURE);

                                            body.stringValue("sub", "test-subject");
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
    @PactTestFor(pactMethod = "validRequestReturnsBavIssuedCredential")
    void fetchVerifiableCredential_whenCalledAgainstBavCri_retrievesAValidVc(MockServer mockServer)
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
                        new BearerAccessToken(VALID_ACCESS_TOKEN), BAV, CRI_OAUTH_SESSION_ITEM);

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
                                                BAV,
                                                credential,
                                                EC_PRIVATE_KEY_JWK,
                                                TEST_ISSUER,
                                                false);

                                JsonNode credentialSubject =
                                        OBJECT_MAPPER
                                                .readTree(vc.getClaimsSet().toString())
                                                .get("vc")
                                                .get("credentialSubject");

                                JsonNode bankAccountNode =
                                        credentialSubject.get("bankAccount").get(0);
                                JsonNode nameParts =
                                        credentialSubject.get("name").get(0).get("nameParts");

                                assertEquals(
                                        "12345678", bankAccountNode.get("accountNumber").asText());
                                assertEquals("103233", bankAccountNode.get("sortCode").asText());

                                assertEquals("GivenName", nameParts.get(0).get("type").asText());
                                assertEquals("FamilyName", nameParts.get(1).get("type").asText());
                                assertEquals("Kenneth", nameParts.get(0).get("value").asText());
                                assertEquals("Decerqueira", nameParts.get(1).get("value").asText());
                            } catch (VerifiableCredentialException | JsonProcessingException e) {
                                throw new RuntimeException(e);
                            }
                        });
    }

    @Pact(provider = "BavCriProvider", consumer = "IpvCoreBack")
    public RequestResponsePact validRequestReturnsBavResponseWithCi(PactDslWithProvider builder) {
        return builder.given("dummyApiKey is a valid api key")
                .given(VALID_ACCESS_TOKEN_FOR_CI + " is a valid access token")
                .given("test-subject is a valid subject")
                .given(TEST_ISSUER + " is the BAV CRI component ID")
                .given("VC evidence failedCheckDetails identityCheckPolicy is none")
                .given("VC evidence failedCheckDetails checkMethod is data")
                .given("VC evidence has a CI of dummyCi")
                .given("VC evidence validityScore is 0")
                .given("VC evidence strengthScore is 3")
                .given("VC evidence txn is dummyTxn")
                .given("VC evidence credentialSubject contains bankAccount")
                .given("VC bankAccount accountNumber is 12345678")
                .given("VC bankAccount sortCode is 103233")
                .given("VC is for Kenneth Decerqueira")
                .uponReceiving("Valid POST request")
                .path("/userinfo")
                .method("POST")
                .headers(
                        "x-api-key",
                        PRIVATE_API_KEY,
                        "Authorization",
                        "Bearer " + VALID_ACCESS_TOKEN_FOR_CI)
                .willRespondWith()
                .status(200)
                .body(
                        newJsonBody(
                                        body -> {
                                            var jwtBuilder =
                                                    new PactJwtBuilder(
                                                            VALID_VC_HEADER,
                                                            FAILED_BAV_VC_BODY,
                                                            FAILED_BAV_VC_SIGNATURE);

                                            body.stringValue("sub", "test-subject");
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
    @PactTestFor(pactMethod = "validRequestReturnsBavResponseWithCi")
    void fetchVerifiableCredential_whenCalledAgainstBavCri_retrievesAVcWithACi(
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
                        new BearerAccessToken(VALID_ACCESS_TOKEN_FOR_CI),
                        BAV,
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
                                                BAV,
                                                credential,
                                                EC_PRIVATE_KEY_JWK,
                                                TEST_ISSUER,
                                                false);

                                JsonNode vcClaim =
                                        OBJECT_MAPPER
                                                .readTree(vc.getClaimsSet().toString())
                                                .get("vc");

                                JsonNode credentialSubject = vcClaim.get("credentialSubject");
                                JsonNode evidence = vcClaim.get("evidence").get(0);

                                JsonNode ciNode = evidence.get("ci");
                                JsonNode nameParts =
                                        credentialSubject.get("name").get(0).get("nameParts");

                                assertEquals("dummyCi", ciNode.get(0).asText());

                                JsonNode bankAccountNode =
                                        credentialSubject.get("bankAccount").get(0);

                                assertEquals(
                                        "12345678", bankAccountNode.get("accountNumber").asText());
                                assertEquals("103233", bankAccountNode.get("sortCode").asText());

                                assertEquals("GivenName", nameParts.get(0).get("type").asText());
                                assertEquals("FamilyName", nameParts.get(1).get("type").asText());
                                assertEquals("Kenneth", nameParts.get(0).get("value").asText());
                                assertEquals("Decerqueira", nameParts.get(1).get("value").asText());
                            } catch (VerifiableCredentialException | JsonProcessingException e) {
                                throw new RuntimeException(e);
                            }
                        });
    }

    @Pact(provider = "BavCriProvider", consumer = "IpvCoreBack")
    public RequestResponsePact invalidAccessTokenReturns401(PactDslWithProvider builder) {
        return builder.given("dummyApiKey is a valid api key")
                .given("dummyInvalidAccessToken is an invalid access token")
                .given("test-subject is a valid subject")
                .given(TEST_ISSUER + " is the BAV CRI component ID")
                .uponReceiving("Invalid POST request due to invalid access token")
                .path("/userinfo")
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
    void fetchVerifiableCredential_whenCalledAgainstBavCriWithInvalidAuthCode_throwsAnException(
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
                                        BAV,
                                        CRI_OAUTH_SESSION_ITEM));

        // Assert
        assertThat(
                exception.getErrorResponse(),
                is(ErrorResponse.FAILED_TO_GET_CREDENTIAL_FROM_ISSUER));
        assertThat(exception.getHttpStatusCode(), is(HTTPResponse.SC_SERVER_ERROR));
    }

    @Pact(provider = "BavCriProvider", consumer = "IpvCoreBack")
    public RequestResponsePact validRequestReturnsValidAccessToken(PactDslWithProvider builder) {
        return builder.given(VALID_AUTH_CODE + " is a valid authorization code")
                .given("dummyApiKey is a valid api key")
                .given("BAV CRI uses CORE_BACK_SIGNING_PRIVATE_KEY_JWK to validate core signatures")
                .given(TEST_ISSUER + " is the BAV CRI component ID")
                .uponReceiving("Valid auth code")
                .path("/token")
                .method("POST")
                .body(
                        "client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer&code="
                                + VALID_AUTH_CODE
                                + "&grant_type=authorization_code&redirect_uri=https%3A%2F%2Fidentity.staging.account.gov.uk%2Fcredential-issuer%2Fcallback%3Fid%3Dbav&client_assertion="
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
                                        body -> {
                                            body.stringType("access_token");
                                            body.stringValue("token_type", "Bearer");
                                            body.integerType("expires_in");
                                        })
                                .build())
                .toPact();
    }

    @Test
    @PactTestFor(pactMethod = "validRequestReturnsValidAccessToken")
    void fetchAccessToken_whenCalledAgainstBavCri_retrievesAValidAccessToken(MockServer mockServer)
            throws URISyntaxException, JOSEException, CriApiException {
        // Arrange
        var credentialIssuerConfig = getMockCredentialIssuerConfig(mockServer);

        when(mockConfigService.getJwtTtlSeconds()).thenReturn(900L);
        when(mockConfigService.getOauthCriConfig(any())).thenReturn(credentialIssuerConfig);
        when(mockConfigService.getSecret(any(), any(String[].class))).thenReturn(PRIVATE_API_KEY);

        // Fix the signature here as mocking out the AWSKMS class inside the real signer would be
        // painful.
        when(mockSignerFactory.getSigner()).thenReturn(mockSigner);
        when(mockSigner.sign(any(), any())).thenReturn(new Base64URL(CLIENT_ASSERTION_SIGNATURE));
        when(mockSigner.supportedJWSAlgorithms()).thenReturn(Set.of(JWSAlgorithm.ES256));
        when(mockSigner.getKid()).thenReturn(CLIENT_ASSERTION_SIGNING_KID);
        when(mockSecureTokenHelper.generate()).thenReturn(SECURE_TOKEN);

        // We need to generate a fixed request, so we set the secure token and expiry to constant
        // values.
        var underTest =
                new CriApiService(
                        mockConfigService,
                        mockSignerFactory,
                        mockSecureTokenHelper,
                        CLIENT_ASSERTION_TIME);

        // Act
        BearerAccessToken accessToken =
                underTest.fetchAccessToken(
                        getCallbackRequest(VALID_AUTH_CODE), CRI_OAUTH_SESSION_ITEM);
        // Assert
        assertThat(accessToken.getType(), is(AccessTokenType.BEARER));
        assertThat(accessToken.getValue(), notNullValue());
        assertThat(accessToken.getLifetime(), greaterThan(0L));
    }

    @Pact(provider = "BavCriProvider", consumer = "IpvCoreBack")
    public RequestResponsePact invalidAuthCodeRequestReturns401(PactDslWithProvider builder) {
        return builder.given("dummyInvalidAuthCode is an invalid authorization code")
                .given("dummyApiKey is a valid api key")
                .given("BAV CRI uses CORE_BACK_SIGNING_PRIVATE_KEY_JWK to validate core signatures")
                .given(TEST_ISSUER + " is the BAV CRI component ID")
                .uponReceiving("Invalid auth code")
                .path("/token")
                .method("POST")
                .body(
                        "client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer&code=dummyInvalidAuthCode&grant_type=authorization_code&redirect_uri=https%3A%2F%2Fidentity.staging.account.gov.uk%2Fcredential-issuer%2Fcallback%3Fid%3Dbav&client_assertion="
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
                .status(401)
                .toPact();
    }

    @Test
    @PactTestFor(pactMethod = "invalidAuthCodeRequestReturns401")
    void fetchAccessToken_whenCalledAgainstBavCriWithInvalidAuthCode_throwsAnException(
            MockServer mockServer) throws URISyntaxException, JOSEException {
        // Arrange
        var credentialIssuerConfig = getMockCredentialIssuerConfig(mockServer);

        when(mockConfigService.getJwtTtlSeconds()).thenReturn(900L);
        when(mockConfigService.getOauthCriConfig(any())).thenReturn(credentialIssuerConfig);
        when(mockConfigService.getSecret(any(), any(String[].class))).thenReturn(PRIVATE_API_KEY);

        // Fix the signature here as mocking out the AWSKMS class inside the real signer would be
        // painful.
        when(mockSignerFactory.getSigner()).thenReturn(mockSigner);
        when(mockSigner.sign(any(), any())).thenReturn(new Base64URL(CLIENT_ASSERTION_SIGNATURE));
        when(mockSigner.supportedJWSAlgorithms()).thenReturn(Set.of(JWSAlgorithm.ES256));
        when(mockSigner.getKid()).thenReturn(CLIENT_ASSERTION_SIGNING_KID);
        when(mockSecureTokenHelper.generate()).thenReturn(SECURE_TOKEN);

        // We need to generate a fixed request, so we set the secure token and expiry to constant
        // values.
        var underTest =
                new CriApiService(
                        mockConfigService,
                        mockSignerFactory,
                        mockSecureTokenHelper,
                        CLIENT_ASSERTION_TIME);

        // Act
        CriApiException exception =
                assertThrows(
                        CriApiException.class,
                        () ->
                                underTest.fetchAccessToken(
                                        getCallbackRequest("dummyInvalidAuthCode"),
                                        CRI_OAUTH_SESSION_ITEM));

        // Assert
        assertThat(exception.getErrorResponse(), is(ErrorResponse.INVALID_TOKEN_REQUEST));
        assertThat(exception.getHttpStatusCode(), is(HTTPResponse.SC_BAD_REQUEST));
    }

    @NotNull
    private static CriCallbackRequest getCallbackRequest(String authCode) {
        return new CriCallbackRequest(
                authCode,
                BAV.getId(),
                "dummySessionId",
                "https://identity.staging.account.gov.uk/credential-issuer/callback?id=bav",
                "dummyState",
                null,
                null,
                "dummyIpAddress",
                "dummyDeviceInformation",
                List.of("dummyFeatureSet"));
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
        Map<String, ContraIndicatorConfig> ciConfigMap = new HashMap<>();
        ciConfigMap.put("dummyCi", ciConfig1);

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
                .credentialUrl(new URI("http://localhost:" + mockServer.getPort() + "/userinfo"))
                .authorizeUrl(new URI("http://localhost:" + mockServer.getPort() + "/authorize"))
                .clientId(IPV_CORE_CLIENT_ID)
                .signingKey(EC_PRIVATE_KEY_JWK)
                .encryptionKey(RSA_ENCRYPTION_PUBLIC_JWK)
                .componentId(TEST_ISSUER)
                .clientCallbackUrl(
                        URI.create(
                                "https://identity.staging.account.gov.uk/credential-issuer/callback?id=bav"))
                .requiresApiKey(true)
                .requiresAdditionalEvidence(false)
                .build();
    }

    private static final String TEST_USER = "test-subject";
    private static final String PRIVATE_API_KEY = "dummyApiKey";
    private static final String VALID_AUTH_CODE = "1e93b714-4838-4ced-9567-6da749f1c616";
    private static final String VALID_ACCESS_TOKEN =
            "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImtpZCJ9.eyJzdWIiOiJhODY0ODliMi0zZjNhLTQ3OTktOTI4MS0zMGU0YjIyMDg2NmQiLCJhdWQiOiJpc3N1ZXIiLCJpc3MiOiJpc3N1ZXIiLCJleHAiOjQ4NjMxMjU0MjR9.KClzxkHU35ck5Wck7jECzt0_TAkiy4iXRrUg_aftDg2uUpLOC0Bnb-77lyTlhSTuotEQbqB1YZqV3X_SotEQbg"; // pragma: allowlist secret
    private static final String VALID_ACCESS_TOKEN_FOR_CI =
            "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImtpZCJ9.eyJzdWIiOiJiODY0ODliMi0zZjNhLTQ3OTktOTI4MS0zMGU0YjIyMDg2NmQiLCJhdWQiOiJkdW1teUJhdkNvbXBvbmVudElkIiwiaXNzIjoiZHVtbXlCYXZDb21wb25lbnRJZCIsImV4cCI6NDg2MzIyNTIwN30.KClzxkHU35ck5Wck7jECzt0_TAkiy4iXRrUg_aftDg2uUpLOC0Bnb-77lyTlhSTuotEQbqB1YZqV3X_SotEQbg"; // pragma: allowlist secret
    private static final Clock CURRENT_TIME =
            Clock.fixed(Instant.parse("2099-01-01T00:00:00.00Z"), ZoneOffset.UTC);
    public static final CriOAuthSessionItem CRI_OAUTH_SESSION_ITEM =
            new CriOAuthSessionItem(
                    "dummySessionId", "dummyOAuthSessionId", BAV.getId(), "dummyConnection", 900);

    // These values have come from the CRI team to make the JWT more realistic and match their test
    // environment
    private static final String IPV_CORE_CLIENT_ID = "https://ipv.core.account.gov.uk";
    private static final String SECURE_TOKEN =
            "8f2eaa7cc25e28d75a1548020aa00eb1"; // pragma: allowlist secret
    private static final String TEST_ISSUER = "https://review-bav.dev.account.gov.uk";
    private static final Clock CLIENT_ASSERTION_TIME =
            Clock.fixed(Instant.parse("2025-05-09T09:02:12.00Z"), ZoneOffset.UTC);
    private static final String CLIENT_ASSERTION_SIGNING_KID =
            // pragma: allowlist nextline secret
            "99915e7a1e122b4fd733da3ce24e527464c97d94211be29fe67087f7465883a6";
    private static final String CLIENT_ASSERTION_HEADER =
            "eyJraWQiOiI5OTkxNWU3YTFlMTIyYjRmZDczM2RhM2NlMjRlNTI3NDY0Yzk3ZDk0MjExYmUyOWZlNjcwODdmNzQ2NTg4M2E2IiwidHlwIjoiSldUIiwiYWxnIjoiRVMyNTYifQ"; // pragma: allowlist secret
    private static final String CLIENT_ASSERTION_BODY =
            "eyJpc3MiOiJodHRwczovL2lwdi5jb3JlLmFjY291bnQuZ292LnVrIiwic3ViIjoiaHR0cHM6Ly9pcHYuY29yZS5hY2NvdW50Lmdvdi51ayIsImF1ZCI6Imh0dHBzOi8vcmV2aWV3LWJhdi5kZXYuYWNjb3VudC5nb3YudWsiLCJleHAiOjE3NDY3ODIyMzIsImp0aSI6IjhmMmVhYTdjYzI1ZTI4ZDc1YTE1NDgwMjBhYTAwZWIxIn0"; // pragma: allowlist secret

    // We generate the signature using EC_PRIVATE_KEY_JWK and jwt.io
    private static final String CLIENT_ASSERTION_SIGNATURE =
            "HBihexLly5jBJA_RU2TBMJMx7kTcx1o4TGL1AxOCWLCcPY08w135MmPVn1zKqchfvGJ5HFv8Q7Iok0E84GXeng"; // pragma: allowlist secret

    // We hardcode the VC headers and bodies like this so that it is easy to update them from JSON
    // sent by the CRI team
    private static final String VALID_VC_HEADER =
            """
            {
              "alg": "ES256",
              "typ": "JWT",
              "kid": "kid"
            }
            """;
    // 2099-01-01 00:00:00 is 4070908800 in epoch seconds
    private static final String VALID_BAV_VC_BODY =
            """
            {
              "nbf": 4070908800,
              "iat": 4070908800,
              "jti": "jti",
              "iss": "https://review-bav.dev.account.gov.uk",
              "sub": "test-subject",
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
                      "value": "1994-01-25"
                    }
                  ],
                  "bankAccount": [
                    {
                      "sortCode": "103233",
                      "accountNumber": "12345678"
                    }
                  ]
                },
                "evidence": [
                  {
                    "type": "IdentityCheck",
                    "strengthScore": 3,
                    "validityScore": 2,
                    "checkDetails": [
                      {
                        "checkMethod": "data",
                        "identityCheckPolicy": "none"
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
    private static final String VALID_BAV_VC_SIGNATURE =
            "GauqZduqYHv4G5cLucdSdfd0vw6sID5FTTzBJPi5Sng9rEh3M3WQtrP_0UtpIrdHo--5CYa-3B2V0KLgmgP24A"; // pragma: allowlist secret

    private static final String FAILED_BAV_VC_BODY =
            """
            {
              "nbf": 4070908800,
              "iat": 4070908800,
              "jti": "jti",
              "iss": "https://review-bav.dev.account.gov.uk",
              "sub": "test-subject",
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
                      "value": "1994-01-25"
                    }
                  ],
                  "bankAccount": [
                    {
                      "sortCode": "103233",
                      "accountNumber": "12345678"
                    }
                  ]
                },
                "evidence": [
                  {
                    "type": "IdentityCheck",
                    "strengthScore": 3,
                    "validityScore": 0,
                    "failedCheckDetails": [
                      {
                        "checkMethod": "data",
                        "identityCheckPolicy": "none"
                      }
                    ],
                    "ci": [
                      "dummyCi"
                    ]
                  }
                ]
              }
            }
            """;
    // If we generate the signature in code it will be different each time, so we need to generate a
    // valid signature (using https://jwt.io works well) and record it here so the PACT file doesn't
    // change each time we run the tests.
    private static final String FAILED_BAV_VC_SIGNATURE =
            "KXPHsN0g6psOx5GswMyKkikmAYKEf9-FeLdSzReUB0mtVY9ZI49Udm9BhspXLYt6rQw83uE4h4G-84CjWqN-GQ"; // pragma: allowlist secret
}
