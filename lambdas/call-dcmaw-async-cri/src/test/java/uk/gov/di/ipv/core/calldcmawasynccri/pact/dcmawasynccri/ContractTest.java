package uk.gov.di.ipv.core.calldcmawasynccri.pact.dcmawasynccri;

import au.com.dius.pact.consumer.MockServer;
import au.com.dius.pact.consumer.dsl.PactDslWithProvider;
import au.com.dius.pact.consumer.junit.MockServerConfig;
import au.com.dius.pact.consumer.junit5.PactConsumerTestExt;
import au.com.dius.pact.consumer.junit5.PactTestFor;
import au.com.dius.pact.core.model.RequestResponsePact;
import au.com.dius.pact.core.model.annotations.Pact;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.token.AccessTokenType;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import org.jetbrains.annotations.NotNull;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.criapiservice.CriApiService;
import uk.gov.di.ipv.core.library.criapiservice.dto.AsyncCredentialRequestBodyDto;
import uk.gov.di.ipv.core.library.criapiservice.exception.CriApiException;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.dto.OauthCriConfig;
import uk.gov.di.ipv.core.library.helpers.SecureTokenHelper;
import uk.gov.di.ipv.core.library.persistence.item.CriOAuthSessionItem;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.signing.SignerFactory;
import uk.gov.di.ipv.core.library.verifiablecredential.domain.VerifiableCredentialStatus;

import java.net.URI;
import java.net.URISyntaxException;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Base64;

import static au.com.dius.pact.consumer.dsl.LambdaDsl.newJsonBody;
import static org.hamcrest.CoreMatchers.is;
import static org.hamcrest.CoreMatchers.notNullValue;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.greaterThan;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.domain.Cri.DCMAW_ASYNC;

@ExtendWith(PactConsumerTestExt.class)
@ExtendWith(MockitoExtension.class)
@PactTestFor(providerName = "DcmawAsyncCriProvider")
@MockServerConfig(hostInterface = "localhost")
class ContractTest {
    @Mock private ConfigService mockConfigService;
    @Mock private SignerFactory mockSignerFactory;
    @Mock private SecureTokenHelper mockSecureTokenHelper;
    @Mock private BearerAccessToken mockBearerAccessToken;
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final String SUBJECT_ID = "dummySubjectId";
    private static final String CALLBACK_URL_TEMPLATE =
            "https://identity.staging.account.gov.uk/app/callback?state=%s";
    private static final String TEST_OAUTH_STATE = "DUMMY_RANDOM_OAUTH_STATE";
    private static final String TEST_ISSUER = "dummyDcmawAsyncComponentId";
    private static final String TEST_ENCRYPTION_KEY = "dummyDcmawAsyncEncryptionKey";
    private static final String IPV_CORE_CLIENT_ID = "ipv-core";
    private static final Clock CURRENT_TIME =
            Clock.fixed(Instant.parse("2099-01-01T00:00:00.00Z"), ZoneOffset.UTC);
    public static final CriOAuthSessionItem CRI_OAUTH_SESSION_ITEM =
            new CriOAuthSessionItem(
                    "dummySessionId",
                    "dummyOAuthSessionId",
                    DCMAW_ASYNC.getId(),
                    "dummyConnection",
                    900);

    @Pact(provider = "DcmawAsyncCriProvider", consumer = "IpvCoreBack")
    public RequestResponsePact validRequestReturnsValidAccessToken(PactDslWithProvider builder) {
        return builder.given("dummySecret is a valid basic auth secret")
                .given("dummyDcmawAsyncComponentId is the dcmaw async CRI component ID")
                .uponReceiving("Valid basic auth credentials")
                .path("/async/token")
                .method("POST")
                .body("grant_type=client_credentials")
                .headers(
                        "Content-Type",
                        "application/x-www-form-urlencoded",
                        "Authorization",
                        getBasicAuthHeaderValue(IPV_CORE_CLIENT_ID, "dummySecret"))
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
    void fetchAccessToken_whenCalledAgainstDcmawAsyncCri_retrievesAValidAccessToken(
            MockServer mockServer) throws URISyntaxException, CriApiException {
        // Arrange
        var credentialIssuerConfig = getMockCredentialIssuerConfig(mockServer);

        when(mockConfigService.getOauthCriConfig(CRI_OAUTH_SESSION_ITEM))
                .thenReturn(credentialIssuerConfig);

        var underTest =
                new CriApiService(
                        mockConfigService, mockSignerFactory, mockSecureTokenHelper, CURRENT_TIME);

        // Act
        BearerAccessToken accessToken =
                underTest.fetchAccessToken(
                        IPV_CORE_CLIENT_ID, "dummySecret", CRI_OAUTH_SESSION_ITEM);

        // Assert
        assertThat(accessToken.getType(), is(AccessTokenType.BEARER));
        assertThat(accessToken.getValue(), notNullValue());
        assertThat(accessToken.getLifetime(), greaterThan(0L));
    }

    @Pact(provider = "DcmawAsyncCriProvider", consumer = "IpvCoreBack")
    public RequestResponsePact invalidRequestReturns400(PactDslWithProvider builder) {
        return builder.given("badDummySecret is not a valid basic auth secret")
                .given("dummyDcmawAsyncComponentId is the dcmaw async CRI component ID")
                .uponReceiving("Invalid basic auth credentials")
                .path("/async/token")
                .method("POST")
                .body("grant_type=client_credentials")
                .headers(
                        "Content-Type",
                        "application/x-www-form-urlencoded",
                        "Authorization",
                        getBasicAuthHeaderValue(IPV_CORE_CLIENT_ID, "badDummySecret"))
                .willRespondWith()
                .status(400)
                .toPact();
    }

    @Test
    @PactTestFor(pactMethod = "invalidRequestReturns400")
    void fetchAccessToken_whenCalledAgainstDcmawAsyncCri_throwsErrorWithInvalidAuthCode(
            MockServer mockServer) throws URISyntaxException {
        // Arrange
        var credentialIssuerConfig = getMockCredentialIssuerConfig(mockServer);

        when(mockConfigService.getOauthCriConfig(CRI_OAUTH_SESSION_ITEM))
                .thenReturn(credentialIssuerConfig);

        var underTest =
                new CriApiService(
                        mockConfigService, mockSignerFactory, mockSecureTokenHelper, CURRENT_TIME);

        // Act
        CriApiException exception =
                assertThrows(
                        CriApiException.class,
                        () -> {
                            underTest.fetchAccessToken(
                                    IPV_CORE_CLIENT_ID, "badDummySecret", CRI_OAUTH_SESSION_ITEM);
                        });
        // Assert
        assertEquals(ErrorResponse.INVALID_TOKEN_REQUEST, exception.getErrorResponse());
        assertEquals(HTTPResponse.SC_BAD_REQUEST, exception.getHttpStatusCode());
    }

    @Pact(provider = "DcmawAsyncCriProvider", consumer = "IpvCoreBack")
    public RequestResponsePact validRequestReturnsPendingCredentialForMamJourney(
            PactDslWithProvider builder) throws Exception {
        return builder.given("dummyAccessToken is a valid access token")
                .given("MAM journey")
                .uponReceiving("Valid credential request")
                .path("/async/credential")
                .method("POST")
                .body(OBJECT_MAPPER.writeValueAsString(getCredentialRequestBody(SUBJECT_ID, true)))
                .headers(
                        "Content-Type",
                        "application/json",
                        "Authorization",
                        "Bearer dummyAccessToken")
                .willRespondWith()
                .status(201)
                .body(
                        newJsonBody(
                                        body -> {
                                            body.stringValue("sub", SUBJECT_ID);
                                            body.stringValue(
                                                    "https://vocab.account.gov.uk/v1/credentialStatus",
                                                    "pending");
                                        })
                                .build())
                .toPact();
    }

    @Test
    @PactTestFor(pactMethod = "validRequestReturnsPendingCredentialForMamJourney")
    void fetchVerifiableCredential_whenCalledAgainstDcmawAsyncCriForMamJourney_retrievesAPendingVc(
            MockServer mockServer)
            throws URISyntaxException, CriApiException, JsonProcessingException {
        // Arrange
        var credentialIssuerConfig = getMockCredentialIssuerConfig(mockServer, true);
        when(mockConfigService.getOauthCriConfig(CRI_OAUTH_SESSION_ITEM))
                .thenReturn(credentialIssuerConfig);

        var underTest =
                new CriApiService(
                        mockConfigService, mockSignerFactory, mockSecureTokenHelper, CURRENT_TIME);

        // Act
        var verifiableCredentialResponse =
                underTest.fetchVerifiableCredential(
                        new BearerAccessToken("dummyAccessToken"),
                        DCMAW_ASYNC,
                        CRI_OAUTH_SESSION_ITEM,
                        getCredentialRequestBody(SUBJECT_ID, true));

        // Assert
        assertEquals(
                VerifiableCredentialStatus.PENDING,
                verifiableCredentialResponse.getCredentialStatus());
    }

    @Pact(provider = "DcmawAsyncCriProvider", consumer = "IpvCoreBack")
    public RequestResponsePact validRequestReturnsPendingCredentialForDadJourney(
            PactDslWithProvider builder) throws Exception {
        return builder.given("dummyAccessToken is a valid access token")
                .given("DAD journey")
                .uponReceiving("Valid credential request")
                .path("/async/credential")
                .method("POST")
                .body(OBJECT_MAPPER.writeValueAsString(getCredentialRequestBody(SUBJECT_ID, false)))
                .headers(
                        "Content-Type",
                        "application/json",
                        "Authorization",
                        "Bearer dummyAccessToken")
                .willRespondWith()
                .status(201)
                .body(
                        newJsonBody(
                                        body -> {
                                            body.stringValue("sub", SUBJECT_ID);
                                            body.stringValue(
                                                    "https://vocab.account.gov.uk/v1/credentialStatus",
                                                    "pending");
                                        })
                                .build())
                .toPact();
    }

    @Test
    @PactTestFor(pactMethod = "validRequestReturnsPendingCredentialForDadJourney")
    void fetchVerifiableCredential_whenCalledAgainstDcmawAsyncCriForDadJourney_retrievesAPendingVc(
            MockServer mockServer)
            throws URISyntaxException, CriApiException, JsonProcessingException {
        // Arrange
        var credentialIssuerConfig = getMockCredentialIssuerConfig(mockServer, false);
        when(mockConfigService.getOauthCriConfig(CRI_OAUTH_SESSION_ITEM))
                .thenReturn(credentialIssuerConfig);

        var underTest =
                new CriApiService(
                        mockConfigService, mockSignerFactory, mockSecureTokenHelper, CURRENT_TIME);

        // Act
        var verifiableCredentialResponse =
                underTest.fetchVerifiableCredential(
                        new BearerAccessToken("dummyAccessToken"),
                        DCMAW_ASYNC,
                        CRI_OAUTH_SESSION_ITEM,
                        getCredentialRequestBody(SUBJECT_ID, false));

        // Assert
        assertEquals(
                VerifiableCredentialStatus.PENDING,
                verifiableCredentialResponse.getCredentialStatus());
    }

    @Pact(provider = "DcmawAsyncCriProvider", consumer = "IpvCoreBack")
    public RequestResponsePact invalidAccessTokenReturns400(PactDslWithProvider builder)
            throws Exception {
        return builder.given("badAccessToken is not a valid access token")
                .uponReceiving("Valid credential request")
                .path("/async/credential")
                .method("POST")
                .body(OBJECT_MAPPER.writeValueAsString(getCredentialRequestBody(SUBJECT_ID)))
                .headers(
                        "Content-Type",
                        "application/json",
                        "Authorization",
                        "Bearer badAccessToken")
                .willRespondWith()
                .status(400)
                .toPact();
    }

    @Test
    @PactTestFor(pactMethod = "invalidAccessTokenReturns400")
    void
            fetchVerifiableCredential_whenCalledAgainstDcmawAsyncCriWithInvalidAccessToken_throwsAnException(
                    MockServer mockServer) throws URISyntaxException {
        // Arrange
        var credentialIssuerConfig = getMockCredentialIssuerConfig(mockServer);
        when(mockConfigService.getOauthCriConfig(CRI_OAUTH_SESSION_ITEM))
                .thenReturn(credentialIssuerConfig);

        var underTest =
                new CriApiService(
                        mockConfigService, mockSignerFactory, mockSecureTokenHelper, CURRENT_TIME);

        // Act
        CriApiException exception =
                assertThrows(
                        CriApiException.class,
                        () ->
                                underTest.fetchVerifiableCredential(
                                        new BearerAccessToken("badAccessToken"),
                                        DCMAW_ASYNC,
                                        CRI_OAUTH_SESSION_ITEM,
                                        getCredentialRequestBody(SUBJECT_ID)));

        // Assert
        assertEquals(
                ErrorResponse.FAILED_TO_GET_CREDENTIAL_FROM_ISSUER, exception.getErrorResponse());
        assertEquals(HTTPResponse.SC_SERVER_ERROR, exception.getHttpStatusCode());
    }

    @Pact(provider = "DcmawAsyncCriProvider", consumer = "IpvCoreBack")
    public RequestResponsePact missingAccessTokenReturns401(PactDslWithProvider builder)
            throws Exception {
        return builder.given("access token is missing")
                .uponReceiving("Valid credential request")
                .path("/async/credential")
                .method("POST")
                .body(OBJECT_MAPPER.writeValueAsString(getCredentialRequestBody(SUBJECT_ID)))
                .headers("Content-Type", "application/json")
                .willRespondWith()
                .status(401)
                .toPact();
    }

    @Test
    @PactTestFor(pactMethod = "missingAccessTokenReturns401")
    void
            fetchVerifiableCredential_whenCalledAgainstDcmawAsyncCriWithMissingAccessToken_throwsAnException(
                    MockServer mockServer) throws URISyntaxException {
        // Arrange
        var credentialIssuerConfig = getMockCredentialIssuerConfig(mockServer);
        when(mockConfigService.getOauthCriConfig(CRI_OAUTH_SESSION_ITEM))
                .thenReturn(credentialIssuerConfig);
        when(mockBearerAccessToken.toAuthorizationHeader()).thenReturn(null);

        var underTest =
                new CriApiService(
                        mockConfigService, mockSignerFactory, mockSecureTokenHelper, CURRENT_TIME);

        // Act
        CriApiException exception =
                assertThrows(
                        CriApiException.class,
                        () ->
                                underTest.fetchVerifiableCredential(
                                        mockBearerAccessToken,
                                        DCMAW_ASYNC,
                                        CRI_OAUTH_SESSION_ITEM,
                                        getCredentialRequestBody(SUBJECT_ID)));

        // Assert
        assertEquals(
                ErrorResponse.FAILED_TO_GET_CREDENTIAL_FROM_ISSUER, exception.getErrorResponse());
        assertEquals(HTTPResponse.SC_SERVER_ERROR, exception.getHttpStatusCode());
    }

    private AsyncCredentialRequestBodyDto getCredentialRequestBody(String userId) {
        return getCredentialRequestBody(userId, true);
    }

    private AsyncCredentialRequestBodyDto getCredentialRequestBody(String userId, boolean isMam) {
        return new AsyncCredentialRequestBodyDto(
                userId,
                "dummyJourneyId",
                IPV_CORE_CLIENT_ID,
                TEST_OAUTH_STATE,
                isMam ? String.format(CALLBACK_URL_TEMPLATE, TEST_OAUTH_STATE) : null);
    }

    @NotNull
    private static OauthCriConfig getMockCredentialIssuerConfig(MockServer mockServer)
            throws URISyntaxException {
        return getMockCredentialIssuerConfig(mockServer, true);
    }

    @NotNull
    private static OauthCriConfig getMockCredentialIssuerConfig(
            MockServer mockServer, boolean isMam) throws URISyntaxException {
        return OauthCriConfig.builder()
                .tokenUrl(new URI("http://localhost:" + mockServer.getPort() + "/async/token"))
                .credentialUrl(
                        new URI("http://localhost:" + mockServer.getPort() + "/async/credential"))
                .authorizeUrl(new URI("http://localhost:" + mockServer.getPort() + "/authorize"))
                .clientId(IPV_CORE_CLIENT_ID)
                .componentId(TEST_ISSUER)
                .encryptionKey(TEST_ENCRYPTION_KEY)
                .clientCallbackUrl(
                        isMam
                                ? URI.create(String.format(CALLBACK_URL_TEMPLATE, TEST_OAUTH_STATE))
                                : null)
                .requiresApiKey(false)
                .requiresAdditionalEvidence(false)
                .build();
    }

    private String getBasicAuthHeaderValue(String clientId, String secret) {
        String idAndSecret = clientId + ":" + secret;
        String encodedIdAndSecret = Base64.getEncoder().encodeToString(idAndSecret.getBytes());
        return "Basic " + encodedIdAndSecret;
    }
}
