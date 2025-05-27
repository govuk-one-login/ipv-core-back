package uk.gov.di.ipv.core.processcricallback.pact.f2fCri;

import au.com.dius.pact.consumer.MockServer;
import au.com.dius.pact.consumer.dsl.PactDslWithProvider;
import au.com.dius.pact.consumer.junit.MockServerConfig;
import au.com.dius.pact.consumer.junit5.PactConsumerTestExt;
import au.com.dius.pact.consumer.junit5.PactTestFor;
import au.com.dius.pact.core.model.RequestResponsePact;
import au.com.dius.pact.core.model.annotations.Pact;
import com.fasterxml.jackson.core.JsonProcessingException;
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
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
import uk.gov.di.ipv.core.library.criapiservice.CriApiService;
import uk.gov.di.ipv.core.library.criapiservice.exception.CriApiException;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.dto.CriCallbackRequest;
import uk.gov.di.ipv.core.library.dto.OauthCriConfig;
import uk.gov.di.ipv.core.library.helpers.SecureTokenHelper;
import uk.gov.di.ipv.core.library.persistence.item.CriOAuthSessionItem;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.signing.CoreSigner;
import uk.gov.di.ipv.core.library.signing.SignerFactory;
import uk.gov.di.ipv.core.library.verifiablecredential.domain.VerifiableCredentialStatus;

import java.net.URI;
import java.net.URISyntaxException;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
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
import static uk.gov.di.ipv.core.library.config.CoreFeatureFlag.KID_JAR_HEADER;
import static uk.gov.di.ipv.core.library.domain.Cri.F2F;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.EC_PRIVATE_KEY_JWK;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.RSA_ENCRYPTION_PUBLIC_JWK;

@ExtendWith(PactConsumerTestExt.class)
@ExtendWith(MockitoExtension.class)
@PactTestFor(providerName = "F2fCriProvider")
@MockServerConfig(hostInterface = "localhost")
class ContractTest {
    @Mock private ConfigService mockConfigService;
    @Mock private SignerFactory mockSignerFactory;
    @Mock private CoreSigner mockSigner;
    @Mock private SecureTokenHelper mockSecureTokenHelper;

    @Pact(provider = "F2fCriProvider", consumer = "IpvCoreBack")
    public RequestResponsePact issueCredentialsUri_returnsValidPendingVc(
            PactDslWithProvider builder) {
        return builder.given("dummyTestUser is a valid subject")
                .given("dummyApiKey is a valid x-api-key")
                .given("74655ce3-a679-4c09-a3b0-1d0dc2eff373 is a valid session ID")
                .given("credentialStatus is pending")
                .uponReceiving("Valid credential request")
                .path("/userinfo")
                .method("POST")
                .headers(
                        "x-api-key",
                        PRIVATE_API_KEY,
                        "Authorization",
                        "Bearer " + DUMMY_ACCESS_TOKEN)
                .willRespondWith()
                .status(202)
                .body(
                        newJsonBody(
                                        body -> {
                                            body.stringValue("sub", "dummyTestUser");
                                            body.stringValue(
                                                    "https://vocab.account.gov.uk/v1/credentialStatus",
                                                    "pending");
                                        })
                                .build())
                .toPact();
    }

    @Test
    @PactTestFor(pactMethod = "issueCredentialsUri_returnsValidPendingVc")
    void testCallToDummyPassportIssueCredential(MockServer mockServer)
            throws URISyntaxException, CriApiException, JsonProcessingException {
        // Arrange
        var credentialIssuerConfig = getMockF2FCredentialIssuerConfig(mockServer);

        when(mockConfigService.getOauthCriConfig(any())).thenReturn(credentialIssuerConfig);
        when(mockConfigService.getSecret(any(), any(String[].class))).thenReturn(PRIVATE_API_KEY);

        // We need to generate a fixed request, so we set the secure token and expiry to constant
        // values.
        var underTest =
                new CriApiService(
                        mockConfigService, mockSignerFactory, mockSecureTokenHelper, CURRENT_TIME);

        // Act
        var verifiableCredentialResponse =
                underTest.fetchVerifiableCredential(
                        new BearerAccessToken(DUMMY_ACCESS_TOKEN),
                        F2F,
                        new CriOAuthSessionItem(
                                "dummySessionId",
                                "dummyOAuthSessionId",
                                F2F.getId(),
                                "dummyConnection",
                                900));

        assertEquals(
                VerifiableCredentialStatus.PENDING,
                verifiableCredentialResponse.getCredentialStatus());
        assertEquals("dummyTestUser", verifiableCredentialResponse.getUserId());
    }

    @Pact(provider = "F2fCriProvider", consumer = "IpvCoreBack")
    public RequestResponsePact validF2FRequestReturnsValidAccessToken(PactDslWithProvider builder) {
        return builder.given("0328ba66-a1b5-4314-acf8-f4673f1f05a2 is a valid authorization code")
                .given("dummyApiKey is a valid api key")
                .given("F2F CRI uses CORE_BACK_SIGNING_PRIVATE_KEY_JWK to validate core signatures")
                .given(TEST_ISSUER + " is the F2F CRI component ID")
                .uponReceiving("Valid auth code")
                .path("/token")
                .method("POST")
                .body(
                        "client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer&code=0328ba66-a1b5-4314-acf8-f4673f1f05a2&grant_type=authorization_code&redirect_uri=https%3A%2F%2Fidentity.staging.account.gov.uk%2Fcredential-issuer%2Fcallback%3Fid%3Df2f&client_assertion="
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
    @PactTestFor(pactMethod = "validF2FRequestReturnsValidAccessToken")
    void fetchAccessToken_whenCalledAgainstF2FCri_retrievesAValidAccessToken(MockServer mockServer)
            throws URISyntaxException, JOSEException, CriApiException {
        // Arrange
        var credentialIssuerConfig = getMockF2FCredentialIssuerConfig(mockServer);

        when(mockConfigService.getLongParameter(ConfigurationVariable.JWT_TTL_SECONDS))
                .thenReturn(900L);
        when(mockConfigService.getOauthCriConfig(any())).thenReturn(credentialIssuerConfig);
        when(mockConfigService.getSecret(any(), any(String[].class))).thenReturn(PRIVATE_API_KEY);
        when(mockConfigService.enabled(KID_JAR_HEADER)).thenReturn(true);

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
                        mockConfigService, mockSignerFactory, mockSecureTokenHelper, CURRENT_TIME);

        // Act
        BearerAccessToken accessToken =
                underTest.fetchAccessToken(
                        new CriCallbackRequest(
                                "0328ba66-a1b5-4314-acf8-f4673f1f05a2",
                                F2F.getId(),
                                "dummySessionId",
                                "https://identity.staging.account.gov.uk/credential-issuer/callback?id=f2f",
                                "dummyState",
                                null,
                                null,
                                "dummyIpAddress",
                                "dummyDeviceInformation",
                                List.of("dummyFeatureSet")),
                        new CriOAuthSessionItem(
                                "dummySessionId",
                                "dummyOAuthSessionId",
                                F2F.getId(),
                                "dummyConnection",
                                900));
        // Assert
        assertThat(accessToken.getType(), is(AccessTokenType.BEARER));
        assertThat(accessToken.getValue(), notNullValue());
        assertThat(accessToken.getLifetime(), greaterThan(0L));
    }

    @Pact(provider = "F2fCriProvider", consumer = "IpvCoreBack")
    public RequestResponsePact invalidAuthCodeRequestReturns401(PactDslWithProvider builder) {
        return builder.given("dummyInvalidAuthCode is an invalid authorization code")
                .given("dummyApiKey is a valid api key")
                .given("grant_type is invalid (auth_code)")
                .given("F2F CRI uses CORE_BACK_SIGNING_PRIVATE_KEY_JWK to validate core signatures")
                .given(TEST_ISSUER + " is the F2F CRI component ID")
                .uponReceiving("Request body with invalid grant_type (auth_code)")
                .path("/token")
                .method("POST")
                .body(
                        "client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer&code=dummyInvalidAuthCode&grant_type=authorization_code&redirect_uri=https%3A%2F%2Fidentity.staging.account.gov.uk%2Fcredential-issuer%2Fcallback%3Fid%3Df2f&client_assertion="
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
    void fetchAccessToken_whenCalledAgainstF2FCri_receivesUnauthorizedWithInvalidAuthCode(
            MockServer mockServer) throws URISyntaxException, JOSEException {
        // Arrange
        var credentialIssuerConfig = getMockF2FCredentialIssuerConfig(mockServer);

        when(mockConfigService.getLongParameter(ConfigurationVariable.JWT_TTL_SECONDS))
                .thenReturn(900L);
        when(mockConfigService.getOauthCriConfig(any())).thenReturn(credentialIssuerConfig);
        when(mockConfigService.getSecret(any(), any(String[].class))).thenReturn(PRIVATE_API_KEY);
        when(mockConfigService.enabled(KID_JAR_HEADER)).thenReturn(true);

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
                        mockConfigService, mockSignerFactory, mockSecureTokenHelper, CURRENT_TIME);

        CriApiException exception =
                assertThrows(
                        CriApiException.class,
                        () -> {
                            underTest.fetchAccessToken(
                                    new CriCallbackRequest(
                                            "dummyInvalidAuthCode",
                                            F2F.getId(),
                                            "dummySessionId",
                                            "https://identity.staging.account.gov.uk/credential-issuer/callback?id=f2f",
                                            "dummyState",
                                            null,
                                            null,
                                            "dummyIpAddress",
                                            "dummyDeviceInformation",
                                            List.of("dummyFeatureSet")),
                                    new CriOAuthSessionItem(
                                            "dummySessionId",
                                            "dummyOAuthSessionId",
                                            F2F.getId(),
                                            "dummyConnection",
                                            900));
                        });

        // Assert
        assertThat(exception.getErrorResponse(), is(ErrorResponse.INVALID_TOKEN_REQUEST));
        assertThat(exception.getHttpStatusCode(), is(HTTPResponse.SC_BAD_REQUEST));
    }

    @NotNull
    private static OauthCriConfig getMockF2FCredentialIssuerConfig(MockServer mockServer)
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
                                "https://identity.staging.account.gov.uk/credential-issuer/callback?id=f2f"))
                .requiresApiKey(true)
                .requiresAdditionalEvidence(false)
                .build();
    }

    private static final String PRIVATE_API_KEY = "dummyApiKey";
    // DUMMY_ACCESS_TOKEN provided by F2F team for subject 74655ce3-a679-4c09-a3b0-1d0dc2eff373
    private static final String DUMMY_ACCESS_TOKEN =
            "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImtpZCJ9.eyJzdWIiOiI3NDY1NWNlMy1hNjc5LTRjMDktYTNiMC0xZDBkYzJlZmYzNzMiLCJhdWQiOiJpc3N1ZXIiLCJpc3MiOiJpc3N1ZXIiLCJleHAiOjIwMjI3OTE3Njd9.KClzxkHU35ck5Wck7jECzt0_TAkiy4iXRrUg_aftDg2uUpLOC0Bnb-77lyTlhSTuotEQbqB1YZqV3X_SotEQbg"; // pragma: allowlist secret

    // These values have come from the CRI team to make the JWT more realistic and match their test
    // environment
    private static final String IPV_CORE_CLIENT_ID = "https://ipv.core.account.gov.uk";
    private static final String TEST_ISSUER = "https://review-o.dev.account.gov.uk";
    private static final String SECURE_TOKEN =
            "35110a7aeacf4d16f1d39d393d9e5d62"; // pragma: allowlist secret
    private static final Clock CURRENT_TIME =
            Clock.fixed(Instant.parse("2025-05-09T08:59:51.00Z"), ZoneOffset.UTC);
    private static final String CLIENT_ASSERTION_SIGNING_KID =
            // pragma: allowlist nextline secret
            "5d6ec7413ae8bf2ea7c416e766ba9b9299b67eaf9e14f984e2f798a48bf6c921";
    private static final String CLIENT_ASSERTION_HEADER =
            "eyJraWQiOiI1ZDZlYzc0MTNhZThiZjJlYTdjNDE2ZTc2NmJhOWI5Mjk5YjY3ZWFmOWUxNGY5ODRlMmY3OThhNDhiZjZjOTIxIiwidHlwIjoiSldUIiwiYWxnIjoiRVMyNTYifQ"; // pragma: allowlist secret
    private static final String CLIENT_ASSERTION_BODY =
            "eyJpc3MiOiJodHRwczovL2lwdi5jb3JlLmFjY291bnQuZ292LnVrIiwic3ViIjoiaHR0cHM6Ly9pcHYuY29yZS5hY2NvdW50Lmdvdi51ayIsImF1ZCI6Imh0dHBzOi8vcmV2aWV3LW8uZGV2LmFjY291bnQuZ292LnVrIiwiZXhwIjoxNzQ2NzgyMDkxLCJqdGkiOiIzNTExMGE3YWVhY2Y0ZDE2ZjFkMzlkMzkzZDllNWQ2MiJ9"; // pragma: allowlist secret

    // We generate the signature using EC_PRIVATE_KEY_JWK and jwt.io
    private static final String CLIENT_ASSERTION_SIGNATURE =
            "diJansVqKvRtOEsZYch1wNd17XPrYYETLjeXRu2HHDadLZJEz6uLoibp2IrChKCZcupETcBBWCPVj8qQYR2VbA"; // pragma: allowlist secret
}
