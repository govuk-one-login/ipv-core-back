package uk.gov.di.ipv.core.issueclientaccesstoken.pact;

import au.com.dius.pact.provider.junit5.HttpTestTarget;
import au.com.dius.pact.provider.junit5.PactVerificationContext;
import au.com.dius.pact.provider.junit5.PactVerificationInvocationContextProvider;
import au.com.dius.pact.provider.junitsupport.Provider;
import au.com.dius.pact.provider.junitsupport.State;
import au.com.dius.pact.provider.junitsupport.loader.PactBroker;
import au.com.dius.pact.provider.junitsupport.loader.PactBrokerAuth;
import au.com.dius.pact.provider.junitsupport.loader.PactBrokerConsumerVersionSelectors;
import au.com.dius.pact.provider.junitsupport.loader.SelectorBuilder;
import com.nimbusds.jose.jwk.ECKey;
import org.apache.commons.codec.digest.DigestUtils;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.TestTemplate;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import uk.gov.di.ipv.core.issueclientaccesstoken.IssueClientAccessTokenHandler;
import uk.gov.di.ipv.core.issueclientaccesstoken.persistance.item.ClientAuthJwtIdItem;
import uk.gov.di.ipv.core.issueclientaccesstoken.service.AccessTokenService;
import uk.gov.di.ipv.core.issueclientaccesstoken.service.ClientAuthJwtIdService;
import uk.gov.di.ipv.core.issueclientaccesstoken.validation.TokenRequestValidator;
import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
import uk.gov.di.ipv.core.library.dto.AuthorizationCodeMetadata;
import uk.gov.di.ipv.core.library.oauthkeyservice.OAuthKeyService;
import uk.gov.di.ipv.core.library.persistence.DataStore;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.retry.Sleeper;
import uk.gov.di.ipv.core.library.service.ClientOAuthSessionDetailsService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.testhelpers.pact.LambdaHttpServer;

import java.io.IOException;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.COMPONENT_ID;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.MAX_ALLOWED_AUTH_CLIENT_TTL;

// To run these tests locally you need to:
// - Obtain the relevant pact file (from the pact broker or another team) and put it in
//   /lambdas/issue-client-access-token/pacts. See the `Running provider pact tests locally` section
// of the README for details on how to get the pact file
// - Comment out the @PactBroker annotation below
// - Uncomment @PactFolder annotation below
@Provider("IpvCoreBackTokenProvider")
@PactBroker(
        url = "${PACT_URL}?testSource=${PACT_BROKER_SOURCE_SECRET_DEV}",
        authentication = @PactBrokerAuth(username = "${PACT_USER}", password = "${PACT_PASSWORD}"))
// @PactFolder("pacts")
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class IssueClientAccessTokenHandlerTest {

    public static final String TEST_CLIENT_ID = "authOrchestrator";
    private LambdaHttpServer httpServer;
    private IpvSessionItem ipvSessionItem;
    @Mock private ConfigService configService;
    @Mock private DataStore<IpvSessionItem> ipvSessionDataStore;
    @Mock private DataStore<ClientOAuthSessionItem> oAuthDataStore;
    @Mock private DataStore<ClientAuthJwtIdItem> jwtIdStore;
    @Mock private Sleeper mockSleeper;
    @Mock private OAuthKeyService mockOauthKeyService;

    @PactBrokerConsumerVersionSelectors
    public static SelectorBuilder consumerVersionSelectors() {
        return new SelectorBuilder().mainBranch();
    }

    @BeforeAll
    static void setupServer() {
        System.setProperty("pact.verifier.publishResults", "true");
        System.setProperty("pact.content_type.override.application/jwt", "text");
    }

    @BeforeEach
    void pactSetup(PactVerificationContext context) throws IOException {

        var accessTokenService = new AccessTokenService(configService);
        var sessionService = new IpvSessionService(ipvSessionDataStore, mockSleeper);
        var clientOAuthSessionService = new ClientOAuthSessionDetailsService(oAuthDataStore);
        var clientAuthJwtIdService = new ClientAuthJwtIdService(jwtIdStore);
        var tokenRequestValidator =
                new TokenRequestValidator(
                        configService, clientAuthJwtIdService, mockOauthKeyService);
        ipvSessionItem = new IpvSessionItem();
        var clientOAuthSessionItem = new ClientOAuthSessionItem();
        var authorizationCodeMetadata = new AuthorizationCodeMetadata();
        authorizationCodeMetadata.setCreationDateTime(
                "2024-02-01T00:00:00.000Z"); // Ensure that the metadata isn't flagged as expired

        when(configService.getLongParameter(MAX_ALLOWED_AUTH_CLIENT_TTL))
                .thenReturn(3153600000L); // 100 years
        when(configService.getLongParameter(ConfigurationVariable.AUTH_CODE_EXPIRY_SECONDS))
                .thenReturn(3153600000L); // 100 years
        when(configService.getLongParameter(ConfigurationVariable.BEARER_TOKEN_TTL))
                .thenReturn(3153600000L); // 100 years
        ipvSessionItem.setClientOAuthSessionId("dummyOuthSessionId");
        when(oAuthDataStore.getItem("dummyOuthSessionId")).thenReturn(clientOAuthSessionItem);
        ipvSessionItem.setAuthorizationCodeMetadata(authorizationCodeMetadata);

        // Set up the web server for the tests
        var handler =
                new IssueClientAccessTokenHandler(
                        accessTokenService,
                        sessionService,
                        configService,
                        clientOAuthSessionService,
                        tokenRequestValidator);

        httpServer = new LambdaHttpServer(handler, "/token");
        httpServer.startServer();

        context.setTarget(new HttpTestTarget("localhost", httpServer.getPort()));
    }

    @AfterEach
    public void tearDown() {
        httpServer.stopServer();
    }

    @State("dummyAuthCode is a valid authorization code")
    public void setAuthCode() {
        when(ipvSessionDataStore.getItemByIndex(
                        "authorizationCode",
                        DigestUtils.sha256Hex(
                                "dummyAuthCode"))) // 56298e46fe43e76f556b5aaea8601d758dd47c084495bf197b985a4e516ac5ce
                .thenReturn(ipvSessionItem);
    }

    @State(
            "the JWT is signed with {\"kty\":\"EC\",\"d\":\"A2cfN3vYKgOQ_r1S6PhGHCLLiVEqUshFYExrxMwkq_A\",\"crv\":\"P-256\",\"kid\":\"14342354354353\",\"x\":\"BMyQQqr3NEFYgb9sEo4hRBje_HHEsy87PbNIBGL4Uiw\",\"y\":\"qoXdkYVomy6HWT6yNLqjHSmYoICs6ioUF565Btx0apw\",\"alg\":\"ES256\"}") // pragma: allowlist secret
    public void setOrchSigningKey() throws Exception {
        var signingKey =
                "{\"kty\":\"EC\",\"d\":\"A2cfN3vYKgOQ_r1S6PhGHCLLiVEqUshFYExrxMwkq_A\",\"crv\":\"P-256\",\"kid\":\"f17da8669a951afc3fb499e901186d77e99af23b5d1962d3ce85e9d6c82d3a69\",\"x\":\"BMyQQqr3NEFYgb9sEo4hRBje_HHEsy87PbNIBGL4Uiw\",\"y\":\"qoXdkYVomy6HWT6yNLqjHSmYoICs6ioUF565Btx0apw\",\"alg\":\"ES256\"}"; // pragma: allowlist secret

        when(mockOauthKeyService.getClientSigningKey(eq(TEST_CLIENT_ID), any()))
                .thenReturn(ECKey.parse(signingKey));
    }

    @State(
            "the JWT is signed with {\"kty\":\"EC\",\"d\":\"4NLo4B5Oj5E_ga6-eYjTSehss85p_mL799NRQqmll64\",\"crv\":\"P-256\",\"kid\":\"f17da8669a951afc3fb499e901186d77e99af23b5d1962d3ce85e9d6c82d3a69\",\"x\":\"emDeRQ0KISC_TdfkoAZdd4lWm2Nk5UOtmmboLEab850\",\"y\":\"-Ua4zzSzMG5lgpMyZoURg6Au60mHSxgnnf9pDtJmE2w\",\"alg\":\"ES256\"}") // pragma: allowlist secret
    public void setAuthSigningKey() throws Exception {
        var signingKey =
                "{\"kty\":\"EC\",\"d\":\"4NLo4B5Oj5E_ga6-eYjTSehss85p_mL799NRQqmll64\",\"crv\":\"P-256\",\"kid\":\"f17da8669a951afc3fb499e901186d77e99af23b5d1962d3ce85e9d6c82d3a69\",\"x\":\"emDeRQ0KISC_TdfkoAZdd4lWm2Nk5UOtmmboLEab850\",\"y\":\"-Ua4zzSzMG5lgpMyZoURg6Au60mHSxgnnf9pDtJmE2w\",\"alg\":\"ES256\"}"; // pragma: allowlist secret

        when(mockOauthKeyService.getClientSigningKey(eq(TEST_CLIENT_ID), any()))
                .thenReturn(ECKey.parse(signingKey));
    }

    @State("dummyInvalidAuthCode is a invalid authorization code")
    public void dontSetAuthCode() {}

    @State("the audience is http://ipv/")
    public void setAudience() {
        when(configService.getParameter(COMPONENT_ID)).thenReturn("http://ipv/");
    }

    @TestTemplate
    @ExtendWith(PactVerificationInvocationContextProvider.class)
    void testMethod(PactVerificationContext context) {
        context.verifyInteraction();
    }
}
