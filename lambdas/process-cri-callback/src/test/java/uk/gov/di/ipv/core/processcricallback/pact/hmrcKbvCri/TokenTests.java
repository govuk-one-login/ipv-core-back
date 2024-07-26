package uk.gov.di.ipv.core.processcricallback.pact.hmrcKbvCri;

import au.com.dius.pact.consumer.MockServer;
import au.com.dius.pact.consumer.dsl.PactDslWithProvider;
import au.com.dius.pact.consumer.junit.MockServerConfig;
import au.com.dius.pact.consumer.junit5.PactConsumerTestExt;
import au.com.dius.pact.consumer.junit5.PactTestFor;
import au.com.dius.pact.core.model.RequestResponsePact;
import au.com.dius.pact.core.model.annotations.Pact;
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
import uk.gov.di.ipv.core.library.criapiservice.CriApiService;
import uk.gov.di.ipv.core.library.criapiservice.exception.CriApiException;
import uk.gov.di.ipv.core.library.dto.CriCallbackRequest;
import uk.gov.di.ipv.core.library.dto.OauthCriConfig;
import uk.gov.di.ipv.core.library.helpers.SecureTokenHelper;
import uk.gov.di.ipv.core.library.kmses256signer.KmsEs256SignerFactory;
import uk.gov.di.ipv.core.library.persistence.item.CriOAuthSessionItem;
import uk.gov.di.ipv.core.library.service.ConfigService;

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
import static uk.gov.di.ipv.core.library.domain.Cri.HMRC_KBV;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.EC_PRIVATE_KEY_JWK;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.EXAMPLE_GENERATED_SECURE_TOKEN;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.RSA_ENCRYPTION_PUBLIC_JWK;

@ExtendWith(PactConsumerTestExt.class)
@ExtendWith(MockitoExtension.class)
@PactTestFor(providerName = "HmrcKbvCriTokenProvider")
@MockServerConfig(hostInterface = "localhost")
class TokenTests {
    @Mock private ConfigService mockConfigService;
    @Mock private KmsEs256SignerFactory mockKmsEs256SignerFactory;
    @Mock private JWSSigner mockSigner;
    @Mock private SecureTokenHelper mockSecureTokenHelper;

    @Pact(provider = "HmrcKbvCriTokenProvider", consumer = "IpvCoreBack")
    public RequestResponsePact validRequestReturnsValidAccessToken(PactDslWithProvider builder) {
        return builder.given("dummyAuthCode is a valid authorization code")
                .given("dummyApiKey is a valid api key")
                .given("dummyHmrcKbvComponentId is the hmrcKbv CRI component ID")
                .given(
                        "HmrcKbv CRI uses CORE_BACK_SIGNING_PRIVATE_KEY_JWK to validate core signatures")
                .uponReceiving("Valid auth code")
                .path("/token")
                .method("POST")
                .body(
                        "client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer&code=dummyAuthCode&grant_type=authorization_code&redirect_uri=https%3A%2F%2Fidentity.staging.account.gov.uk%2Fcredential-issuer%2Fcallback%3Fid%3DhmrcKbv&client_assertion=" // pragma: allowlist secret
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
    void fetchAccessToken_whenCalledAgainstHmrcKbvCri_retrievesAValidAccessToken(
            MockServer mockServer) throws URISyntaxException, JOSEException, CriApiException {
        // Arrange
        var credentialIssuerConfig = getMockCredentialIssuerConfig(mockServer);

        when(mockConfigService.getParameter(ConfigurationVariable.JWT_TTL_SECONDS))
                .thenReturn("900");
        when(mockConfigService.getOauthCriConfig(any())).thenReturn(credentialIssuerConfig);
        when(mockConfigService.getApiKeySecret(any(), any(String[].class)))
                .thenReturn(PRIVATE_API_KEY);

        // Signature generated by jwt.io by debugging the test and getting the client assertion JWT
        // generated by the test as mocking out the AWSKMS class inside the real signer would be
        // painful.
        when(mockKmsEs256SignerFactory.getSigner(any())).thenReturn(mockSigner);
        when(mockSigner.sign(any(), any())).thenReturn(new Base64URL(CLIENT_ASSERTION_SIGNATURE));
        when(mockSigner.supportedJWSAlgorithms()).thenReturn(Set.of(JWSAlgorithm.ES256));
        when(mockSecureTokenHelper.generate()).thenReturn(EXAMPLE_GENERATED_SECURE_TOKEN);

        // We need to generate a fixed request, so we set the secure token and expiry to constant
        // values.
        var underTest =
                new CriApiService(
                        mockConfigService,
                        mockKmsEs256SignerFactory,
                        mockSecureTokenHelper,
                        CURRENT_TIME);

        // Act
        BearerAccessToken accessToken =
                underTest.fetchAccessToken(
                        getCallbackRequest("dummyAuthCode"), getCriOAuthSessionItem());
        // Assert
        assertThat(accessToken.getType(), is(AccessTokenType.BEARER));
        assertThat(accessToken.getValue(), notNullValue());
        assertThat(accessToken.getLifetime(), greaterThan(0L));
    }

    @Pact(provider = "HmrcKbvCriTokenProvider", consumer = "IpvCoreBack")
    public RequestResponsePact invalidAuthCodeRequestReturns400(PactDslWithProvider builder) {
        return builder.given("dummyInvalidAuthCode is an invalid authorization code")
                .given("dummyApiKey is a valid api key")
                .given("dummyHmrcKbvComponentId is the hmrcKbv CRI component ID")
                .given(
                        "HmrcKbv CRI uses CORE_BACK_SIGNING_PRIVATE_KEY_JWK to validate core signatures")
                .uponReceiving("Invalid authorization code")
                .path("/token")
                .method("POST")
                .body(
                        "client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer&code=dummyInvalidAuthCode&grant_type=authorization_code&redirect_uri=https%3A%2F%2Fidentity.staging.account.gov.uk%2Fcredential-issuer%2Fcallback%3Fid%3DhmrcKbv&client_assertion="
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
    void fetchAccessToken_whenCalledAgainstHmrcKbvCriWithInvalidAuthCode_throwsAnException(
            MockServer mockServer) throws URISyntaxException, JOSEException {

        // Arrange
        var credentialIssuerConfig = getMockCredentialIssuerConfig(mockServer);

        when(mockConfigService.getParameter(ConfigurationVariable.JWT_TTL_SECONDS))
                .thenReturn("900");
        when(mockConfigService.getOauthCriConfig(any())).thenReturn(credentialIssuerConfig);
        when(mockConfigService.getApiKeySecret(any(), any(String[].class)))
                .thenReturn(PRIVATE_API_KEY);

        // Signature generated by jwt.io by debugging the test and getting the client assertion
        // JWT
        // generated by the test as mocking out the AWSKMS class inside the real signer would be
        // painful.
        when(mockKmsEs256SignerFactory.getSigner(any())).thenReturn(mockSigner);
        when(mockSigner.sign(any(), any())).thenReturn(new Base64URL(CLIENT_ASSERTION_SIGNATURE));
        when(mockSigner.supportedJWSAlgorithms()).thenReturn(Set.of(JWSAlgorithm.ES256));
        when(mockSecureTokenHelper.generate()).thenReturn(EXAMPLE_GENERATED_SECURE_TOKEN);

        // We need to generate a fixed request, so we set the secure token and expiry to
        // constant
        // values.
        var underTest =
                new CriApiService(
                        mockConfigService,
                        mockKmsEs256SignerFactory,
                        mockSecureTokenHelper,
                        CURRENT_TIME);

        // Act
        CriApiException exception =
                assertThrows(
                        CriApiException.class,
                        () ->
                                underTest.fetchAccessToken(
                                        getCallbackRequest("dummyInvalidAuthCode"),
                                        getCriOAuthSessionItem()));

        // Assert
        assertEquals("Invalid token request", exception.getErrorResponse().getMessage());
        assertEquals(400, exception.getHttpStatusCode());
    }

    @NotNull
    private static CriOAuthSessionItem getCriOAuthSessionItem() {
        return new CriOAuthSessionItem(
                "dummySessionId", "dummyOAuthSessionId", HMRC_KBV.getId(), "dummyConnection", 900);
    }

    @NotNull
    private static CriCallbackRequest getCallbackRequest(String authCode) {
        return new CriCallbackRequest(
                authCode,
                HMRC_KBV.getId(),
                "dummySessionId",
                "https://identity.staging.account.gov.uk/credential-issuer/callback?id=hmrcKbv",
                "dummyState",
                null,
                null,
                "dummyIpAddress",
                "dummyDeviceInformation",
                List.of("dummyFeatureSet"));
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

    private static final String TEST_ISSUER = "dummyHmrcKbvComponentId";
    private static final String IPV_CORE_CLIENT_ID = "ipv-core";
    private static final String PRIVATE_API_KEY = "dummyApiKey";
    private static final Clock CURRENT_TIME =
            Clock.fixed(Instant.parse("2099-01-01T00:00:00.00Z"), ZoneOffset.UTC);

    private static final String CLIENT_ASSERTION_HEADER = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9";
    private static final String CLIENT_ASSERTION_BODY =
            "eyJpc3MiOiJpcHYtY29yZSIsInN1YiI6Imlwdi1jb3JlIiwiYXVkIjoiZHVtbXlIbXJjS2J2Q29tcG9uZW50SWQiLCJleHAiOjQwNzA5MDk3MDAsImp0aSI6IlNjbkY0ZEdYdGhaWVhTXzVrODVPYkVvU1UwNFctSDNxYV9wNm5wdjJaVVkifQ"; // pragma: allowlist secret
    // Signature generated using JWT.io
    private static final String CLIENT_ASSERTION_SIGNATURE =
            "Qm36kQ8RhRM4iu4PVvRqXFqrBJ6qo65NMjxwTgaMBaFNTGb_u8OX_Cbcn6Vn88Wl_6l0jCUCcxh8U5o8Ns7fEw"; // pragma: allowlist secret
}
