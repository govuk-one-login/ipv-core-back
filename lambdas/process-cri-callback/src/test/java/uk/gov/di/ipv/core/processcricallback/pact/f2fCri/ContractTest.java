package uk.gov.di.ipv.core.processcricallback.pact.f2fCri;

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
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.token.AccessTokenType;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.dto.CredentialIssuerConfig;
import uk.gov.di.ipv.core.library.dto.CriCallbackRequest;
import uk.gov.di.ipv.core.library.helpers.SecureTokenHelper;
import uk.gov.di.ipv.core.library.persistence.item.CriOAuthSessionItem;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.verifiablecredential.domain.VerifiableCredentialStatus;
import uk.gov.di.ipv.core.processcricallback.exception.CriApiException;
import uk.gov.di.ipv.core.processcricallback.service.CriApiService;

import java.net.URI;
import java.net.URISyntaxException;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
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
public class ContractTest {
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
    @Mock private ConfigService mockConfigService;
    @Mock private JWSSigner mockSigner;
    @Mock private SecureTokenHelper mockSecureTokenHelper;

    @Pact(provider = "F2fCriProvider", consumer = "IpvCoreBack")
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

    @Pact(provider = "F2fCriProvider", consumer = "IpvCoreBack")
    public RequestResponsePact invalidAuthCode_F2FRequestReturnsBadRequest(
            PactDslWithProvider builder) {
        return builder.given("dummyAuthCode is a valid authorization code")
                .given("dummyApiKey is a valid api key")
                .given("grant_type is invalid (auth_code)")
                .given("dummyF2fComponentId is the F2F CRI component ID")
                .given("F2F CRI uses CORE_BACK_SIGNING_PRIVATE_KEY_JWK to validate core signatures")
                .uponReceiving("Request body with invalid grant_type (auth_code)")
                .path("/token")
                .method("POST")
                .body(
                        "client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer&code=dummyInvalidAuthCode&grant_type=authorization_code&redirect_uri=https%3A%2F%2Fidentity.staging.account.gov.uk%2Fcredential-issuer%2Fcallback%3Fid%3Df2f&client_assertion=eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJpcHYtY29yZSIsInN1YiI6Imlwdi1jb3JlIiwiYXVkIjoiZHVtbXlGMmZDb21wb25lbnRJZCIsImV4cCI6NDA3MDkwOTcwMCwianRpIjoiU2NuRjRkR1h0aFpZWFNfNWs4NU9iRW9TVTA0Vy1IM3FhX3A2bnB2MlpVWSJ9.hXYrKJ_W9YItUbZxu3T63gQgScVoSMqHZ43UPfdB8im8L4d0mZPLC6BlwMJSsfjiAyU1y3c37vm-rV8kZo2uyw")
                .headers(
                        "x-api-key",
                        PRIVATE_API_KEY,
                        "Content-Type",
                        "application/x-www-form-urlencoded; charset=UTF-8")
                .willRespondWith()
                .status(401)
                .toPact();
    }

    @Pact(provider = "F2fCriProvider", consumer = "IpvCoreBack")
    public RequestResponsePact missingRedirectUri_F2FRequestReturnsValidAccessToken(
            PactDslWithProvider builder) {
        return builder.given("dummyAuthCode is a valid authorization code")
                .given("dummyApiKey is a valid api key")
                .given("redirect_uri is missing")
                .given("dummyF2fComponentId is the F2F CRI component ID")
                .given("F2F CRI uses CORE_BACK_SIGNING_PRIVATE_KEY_JWK to validate core signatures")
                .uponReceiving("Request body with missing redirect_uri parameter")
                .path("/token")
                .method("POST")
                .body(
                        "client_assertion_type=urn%3Aietf%3Aparams%3Aoauth%3Aclient-assertion-type%3Ajwt-bearer&code=dummyAuthCode&grant_type=authorization_code&client_assertion=eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiJ9.eyJpc3MiOiJpcHYtY29yZSIsInN1YiI6Imlwdi1jb3JlIiwiYXVkIjoiZHVtbXlGMmZDb21wb25lbnRJZCIsImV4cCI6NDA3MDkwOTcwMCwianRpIjoiU2NuRjRkR1h0aFpZWFNfNWs4NU9iRW9TVTA0Vy1IM3FhX3A2bnB2MlpVWSJ9.hXYrKJ_W9YItUbZxu3T63gQgScVoSMqHZ43UPfdB8im8L4d0mZPLC6BlwMJSsfjiAyU1y3c37vm-rV8kZo2uyw")
                .headers(
                        "x-api-key",
                        PRIVATE_API_KEY,
                        "Content-Type",
                        "application/x-www-form-urlencoded; charset=UTF-8")
                .willRespondWith()
                .status(401)
                .toPact();
    }

    @Pact(provider = "F2fCriProvider", consumer = "IPVCoreBack")
    public RequestResponsePact issueCredentialsUri_returnsValidPendingVc(
            PactDslWithProvider builder) {
        final String pendingResponse =
                "{\"sub\":\""
                        + "dummyTestUser"
                        + "\",\"https://vocab.account.gov.uk/v1/credentialStatus\":\"pending\"}";

        return builder.given("")
                .uponReceiving("Valid credential request body")
                .path("/credential")
                .method("POST")
                .headers("x-api-key", PRIVATE_API_KEY, "Authorization", "Bearer dummyAccessToken")
                .willRespondWith()
                .status(200)
                .body(
                        newJsonBody(
                                        (body) -> {
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
            throws URISyntaxException, CriApiException {
        // Arrange
        var credentialIssuerConfig =
                getMockF2FCredentialIssuerConfig(
                        mockServer,
                        URI.create(
                                "https://identity.staging.account.gov.uk/credential-issuer/callback?id=f2f"));

        when(mockConfigService.getCriConfig(any())).thenReturn(credentialIssuerConfig);
        when(mockConfigService.getCriPrivateApiKey(any())).thenReturn(PRIVATE_API_KEY);

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

        assertEquals(
                verifiableCredentialResponse.getCredentialStatus(),
                VerifiableCredentialStatus.PENDING);
        assertEquals(verifiableCredentialResponse.getUserId(), "dummyTestUser");
    }

    @Test
    @PactTestFor(pactMethod = "validF2FRequestReturnsValidAccessToken")
    void fetchAccessToken_whenCalledAgainstF2FCri_retrievesAValidAccessToken(MockServer mockServer)
            throws URISyntaxException, JOSEException, CriApiException {
        // Arrange
        var credentialIssuerConfig =
                getMockF2FCredentialIssuerConfig(
                        mockServer,
                        URI.create(
                                "https://identity.staging.account.gov.uk/credential-issuer/callback?id=f2f"));

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
    @PactTestFor(pactMethod = "invalidAuthCode_F2FRequestReturnsBadRequest")
    void fetchAccessToken_whenCalledAgainstF2FCri_receivesUnauthorizedWithInvalidAuthCode(
            MockServer mockServer) throws URISyntaxException, JOSEException {
        // Arrange
        var credentialIssuerConfig =
                getMockF2FCredentialIssuerConfig(
                        mockServer,
                        URI.create(
                                "https://identity.staging.account.gov.uk/credential-issuer/callback?id=f2f"));

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

        CriApiException exception =
                assertThrows(
                        CriApiException.class,
                        () -> {
                            underTest.fetchAccessToken(
                                    new CriCallbackRequest(
                                            "dummyInvalidAuthCode",
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
                        });

        // Assert
        assertThat(exception.getErrorResponse(), is(ErrorResponse.INVALID_TOKEN_REQUEST));
        assertThat(exception.getHttpStatusCode(), is(HTTPResponse.SC_BAD_REQUEST));
    }

    @Test
    @PactTestFor(pactMethod = "missingRedirectUri_F2FRequestReturnsValidAccessToken")
    void fetchAccessToken_whenCalledAgainstF2FCri_receivesBadRequestWithMissingRedirectUri(
            MockServer mockServer) throws URISyntaxException, JOSEException {
        // Arrange
        var credentialIssuerConfig = getMockF2FCredentialIssuerConfig(mockServer, null);

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

        CriApiException exception =
                assertThrows(
                        CriApiException.class,
                        () -> {
                            underTest.fetchAccessToken(
                                    new CriCallbackRequest(
                                            "dummyAuthCode",
                                            credentialIssuerConfig.getClientId(),
                                            "dummySessionId",
                                            null,
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
                        });

        // Assert
        assertThat(exception.getErrorResponse(), is(ErrorResponse.INVALID_TOKEN_REQUEST));
        assertThat(exception.getHttpStatusCode(), is(HTTPResponse.SC_BAD_REQUEST));
    }

    @NotNull
    private static CredentialIssuerConfig getMockF2FCredentialIssuerConfig(
            MockServer mockServer, URI clientCallbackUrl) throws URISyntaxException {
        return new CredentialIssuerConfig(
                new URI("http://localhost:" + mockServer.getPort() + "/token"),
                new URI("http://localhost:" + mockServer.getPort() + "/credential"),
                new URI("http://localhost:" + mockServer.getPort() + "/authorize"),
                IPV_CORE_CLIENT_ID,
                CRI_SIGNING_PRIVATE_KEY_JWK,
                CRI_RSA_ENCRYPTION_PUBLIC_JWK,
                "dummyF2fComponentId",
                clientCallbackUrl,
                true,
                false);
    }
}
