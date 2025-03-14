package uk.gov.di.ipv.core.userreverification.pact;

import au.com.dius.pact.provider.junit5.HttpTestTarget;
import au.com.dius.pact.provider.junit5.PactVerificationContext;
import au.com.dius.pact.provider.junit5.PactVerificationInvocationContextProvider;
import au.com.dius.pact.provider.junitsupport.Provider;
import au.com.dius.pact.provider.junitsupport.State;
import au.com.dius.pact.provider.junitsupport.loader.PactBroker;
import au.com.dius.pact.provider.junitsupport.loader.PactBrokerAuth;
import au.com.dius.pact.provider.junitsupport.loader.PactBrokerConsumerVersionSelectors;
import au.com.dius.pact.provider.junitsupport.loader.SelectorBuilder;
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
import uk.gov.di.ipv.core.library.dto.AccessTokenMetadata;
import uk.gov.di.ipv.core.library.persistence.DataStore;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.retry.Sleeper;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.ClientOAuthSessionDetailsService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.testhelpers.pact.LambdaHttpServer;
import uk.gov.di.ipv.core.library.verifiablecredential.service.SessionCredentialsService;
import uk.gov.di.ipv.core.userreverification.UserReverificationHandler;

import java.io.IOException;

import static org.mockito.Mockito.when;

// To run these tests locally you need to:
// - Obtain the relevant pact file (from the pact broker or another team) and put it in
//   /lambdas/build-user-identity/pacts. See the `Running provider pact tests locally` section of
//   the README for details on how to get the pact file
// - Comment out the @PactBroker annotation below
// - Uncomment @PactFolder annotation below
@Provider("IpvCoreBackReverificationProvider")
@PactBroker(
        url = "${PACT_URL}?testSource=${PACT_BROKER_SOURCE_SECRET_DEV}",
        authentication = @PactBrokerAuth(username = "${PACT_USER}", password = "${PACT_PASSWORD}"))
// @PactFolder("pacts")
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
public class UserReverificationHandlerTest {
    private static final String IPV_SESSION_ID = "mockIpvSessionId";
    private static final String CLIENT_OAUTH_SESSION_ID = "mockClientOAuthSessionId";
    private static final String REVERIFICATION_SCOPE = "reverification";

    private LambdaHttpServer httpServer;

    @Mock private Sleeper mockSleeper;
    @Mock private DataStore<IpvSessionItem> mockIpvSessionDataStore;
    @Mock private ConfigService mockConfigService;
    @Mock private AuditService mockAuditService;
    @Mock private DataStore<ClientOAuthSessionItem> mockOAuthSessionStore;
    @Mock private SessionCredentialsService mockSessionCredentialsService;

    @PactBrokerConsumerVersionSelectors
    public static SelectorBuilder consumerVersionSelectors() {
        return new SelectorBuilder().mainBranch();
    }

    @BeforeAll
    static void setupServer() {
        System.setProperty("pact.content_type.override.application/jwt", "text");
    }

    @BeforeEach
    void pactSetup(PactVerificationContext context) throws IOException {
        var ipvSessionService = new IpvSessionService(mockIpvSessionDataStore, mockSleeper);
        var clientOAuthSessionDetailsService =
                new ClientOAuthSessionDetailsService(mockOAuthSessionStore);

        var handler =
                new UserReverificationHandler(
                        ipvSessionService,
                        mockConfigService,
                        clientOAuthSessionDetailsService,
                        mockSessionCredentialsService,
                        mockAuditService);

        httpServer = new LambdaHttpServer(handler, "/reverification");
        httpServer.startServer();

        context.setTarget(new HttpTestTarget("localhost", httpServer.getPort()));
    }

    @AfterEach
    public void tearDown() {
        httpServer.stopServer();
    }

    @State("accessToken is a valid access token")
    public void setAccessToken() {
        var ipvSession = new IpvSessionItem();
        ipvSession.setIpvSessionId(IPV_SESSION_ID);
        ipvSession.setClientOAuthSessionId("mockClientOAuthSessionId");
        ipvSession.setAccessTokenMetadata(new AccessTokenMetadata());

        var oAuthSession = new ClientOAuthSessionItem();
        oAuthSession.setUserId("mockUserId");
        oAuthSession.setClientId("mockClientId");
        oAuthSession.setGovukSigninJourneyId(CLIENT_OAUTH_SESSION_ID);
        oAuthSession.setScope(REVERIFICATION_SCOPE);

        when(mockOAuthSessionStore.getItem(CLIENT_OAUTH_SESSION_ID)).thenReturn(oAuthSession);
        when(mockIpvSessionDataStore.getItemByIndex(
                        "accessToken", DigestUtils.sha256Hex("accessToken")))
                .thenReturn(ipvSession);
    }

    @State("accessToken is a invalid access token")
    public void dontSetAccessToken() {
        /*
            This method is empty - access tokens are invalid by default
        */
    }

    @TestTemplate
    @ExtendWith(PactVerificationInvocationContextProvider.class)
    void testMethod(PactVerificationContext context) {
        context.verifyInteraction();
    }
}
