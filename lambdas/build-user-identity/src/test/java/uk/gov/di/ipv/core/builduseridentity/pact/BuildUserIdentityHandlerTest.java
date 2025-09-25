package uk.gov.di.ipv.core.builduseridentity.pact;

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
import uk.gov.di.ipv.core.builduseridentity.BuildUserIdentityHandler;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.dto.AccessTokenMetadata;
import uk.gov.di.ipv.core.library.enums.Vot;
import uk.gov.di.ipv.core.library.exceptions.CiExtractionException;
import uk.gov.di.ipv.core.library.exceptions.CredentialParseException;
import uk.gov.di.ipv.core.library.persistence.DataStore;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.SessionCredentialItem;
import uk.gov.di.ipv.core.library.retry.Sleeper;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.CimitUtilityService;
import uk.gov.di.ipv.core.library.service.ClientOAuthSessionDetailsService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.testhelpers.pact.LambdaHttpServer;
import uk.gov.di.ipv.core.library.testhelpers.pact.PactJwtBuilder;
import uk.gov.di.ipv.core.library.useridentity.service.UserIdentityService;
import uk.gov.di.ipv.core.library.verifiablecredential.service.SessionCredentialsService;

import java.io.IOException;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;

import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.domain.Cri.ADDRESS;
import static uk.gov.di.ipv.core.library.domain.Cri.DCMAW;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.SIGNED_CIMIT_VC_NO_CI;

// To run these tests locally you need to:
// - Obtain the relevant pact file (from the pact broker or another team) and put it in
//   /lambdas/build-user-identity/pacts. See the `Running provider pact tests locally` section of
//   the README for details on how to get the pact file
// - Comment out the @PactBroker annotation below
// - Uncomment @PactFolder annotation below
@Provider("IpvCoreBackUserIdentityProvider")
@PactBroker(
        url = "${PACT_URL}?testSource=${PACT_BROKER_SOURCE_SECRET_DEV}",
        authentication = @PactBrokerAuth(username = "${PACT_USER}", password = "${PACT_PASSWORD}"))
// @PactFolder("pacts")
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class BuildUserIdentityHandlerTest {

    private static final String IPV_SESSION_ID = "dummyIpvSessionId";

    private LambdaHttpServer httpServer;
    @Mock private ConfigService mockConfigService;
    @Mock private AuditService mockAuditService;
    @Mock private DataStore<IpvSessionItem> mockIpvSessionDataStore;
    @Mock private DataStore<SessionCredentialItem> mockSessionCredentialItemStore;
    @Mock private DataStore<ClientOAuthSessionItem> mockOAuthSessionStore;
    @Mock private CimitUtilityService mockCimitUtilityService;
    @Mock private SessionCredentialsService mockSessionCredentialsService;
    @Mock private Sleeper mockSleeper;

    @PactBrokerConsumerVersionSelectors
    public static SelectorBuilder consumerVersionSelectors() {
        return new SelectorBuilder().mainBranch();
    }

    @BeforeAll
    static void setupServer() {
        System.setProperty("pact.content_type.override.application/jwt", "text");
    }

    @BeforeEach
    void pactSetup(PactVerificationContext context)
            throws IOException, ParseException, CredentialParseException, CiExtractionException {

        var userIdentityService = new UserIdentityService(mockConfigService);
        var ipvSessionService = new IpvSessionService(mockIpvSessionDataStore, mockSleeper);
        var clientOAuthSessionDetailsService =
                new ClientOAuthSessionDetailsService(mockOAuthSessionStore, mockConfigService);

        // Configure CIMIT service to return VC and no CIs
        var jwtBuilder =
                new PactJwtBuilder(VC_HEADER, CIMIT_VC_NO_CIS_BODY, CIMIT_VC_NO_CIS_SIGNATURE);
        var cimitVc = VerifiableCredential.fromValidJwt(null, null, jwtBuilder.buildSignedJwt());

        when(mockCimitUtilityService.getContraIndicatorsFromVc(cimitVc)).thenReturn(List.of());

        // Configure the config service
        when(mockConfigService.getCoreVtmClaim()).thenReturn("dummyVtmClaim");

        var passportVcBuilder =
                new PactJwtBuilder(
                        VC_HEADER, VALID_UK_PASSPORT_VC_BODY, VALID_UK_PASSPORT_VC_SIGNATURE);
        var addressVcBuilder =
                new PactJwtBuilder(VC_HEADER, VALID_ADDRESS_VC_BODY, VALID_ADDRESS_VC_SIGNATURE);

        List<SessionCredentialItem> sessionCredentials = new ArrayList<>();
        var passportCredential =
                new SessionCredentialItem(
                        IPV_SESSION_ID, DCMAW, passportVcBuilder.buildSignedJwt(), true, null);
        var addressCredential =
                new SessionCredentialItem(
                        IPV_SESSION_ID, ADDRESS, addressVcBuilder.buildSignedJwt(), true, null);
        sessionCredentials.add(passportCredential);
        sessionCredentials.add(addressCredential);

        when(mockSessionCredentialItemStore.getItems(IPV_SESSION_ID))
                .thenReturn(sessionCredentials);

        var sessionCredentialService =
                new SessionCredentialsService(mockSessionCredentialItemStore);

        // Set up the web server for the tests
        var handler =
                new BuildUserIdentityHandler(
                        userIdentityService,
                        ipvSessionService,
                        mockConfigService,
                        mockAuditService,
                        clientOAuthSessionDetailsService,
                        mockCimitUtilityService,
                        sessionCredentialService);

        httpServer = new LambdaHttpServer(handler, "/user-identity");
        httpServer.startServer();

        context.setTarget(new HttpTestTarget("localhost", httpServer.getPort()));
    }

    @AfterEach
    public void tearDown() {
        httpServer.stopServer();
    }

    @State("send user identity request to IPV")
    public void setAuthCode() {}

    @State("accessToken is a valid access token")
    public void setAccessToken() {
        var ipvSession = new IpvSessionItem();
        ipvSession.setIpvSessionId(IPV_SESSION_ID);
        ipvSession.setClientOAuthSessionId("dummyClientOAuthSessionId");
        ipvSession.setVot(Vot.P2);
        ipvSession.setSecurityCheckCredential(SIGNED_CIMIT_VC_NO_CI);
        ipvSession.setAccessTokenMetadata(new AccessTokenMetadata());

        var oAuthSession = new ClientOAuthSessionItem();
        oAuthSession.setUserId("dummyOAuthUserId");
        oAuthSession.setClientId("dummyOAuthClientId");
        oAuthSession.setGovukSigninJourneyId("dummySigninJourneyId");
        oAuthSession.setScope("openid");
        oAuthSession.setVtr(List.of("P2"));

        when(mockOAuthSessionStore.getItem("dummyClientOAuthSessionId")).thenReturn(oAuthSession);
        when(mockIpvSessionDataStore.getItemByIndex(
                        "accessToken", DigestUtils.sha256Hex("accessToken")))
                .thenReturn(ipvSession);
    }

    @State("accessToken is a invalid access token")
    public void dontSetAccessToken() {}

    @TestTemplate
    @ExtendWith(PactVerificationInvocationContextProvider.class)
    void testMethod(PactVerificationContext context) {
        context.verifyInteraction();
    }

    private static final String VC_HEADER =
            """
            {
              "alg": "ES256",
              "typ": "JWT"
            }
            """;

    private static final String CIMIT_VC_NO_CIS_BODY =
            """
            {
              "sub": "urn:fdc:example.gov.uk:2022:1234",
              "iss": "https://identity.staging.account.gov.uk/",
              "nbf": 1541493724,
              "exp": 1573029723,
              "vc": {
                "type": [
                  "VerifiableCredential",
                  "SecurityCheckCredential"
                ],
                "evidence": [
                  {
                    "type": "SecurityCheck"
                  }
                ]
              }
            }
            """;

    private static final String CIMIT_VC_NO_CIS_SIGNATURE =
            "q9bLcKWe9K13QJoJL-f8Lz4UdhUGfzQgXPtsmu5TK5W2mP4mr7oXJjqKBAUPypnZdWza1zdKZiQpAmmVy1BW3A"; // pragma: allowlist secret

    // 2099-01-01 00:00:00 is 4070908800 in epoch seconds
    // From DCMAW-3079-AC1
    private static final String VALID_UK_PASSPORT_VC_BODY =
            """
            {
              "sub": "test-subject",
              "iss": "dummyDcmawComponentId",
              "nbf": 4070908800,
              "exp": 4070909400,
              "vc": {
                "@context": [
                  "https://www.w3.org/2018/credentials/v1",
                  "https://vocab.account.gov.uk/contexts/identity-v1.jsonld"
                ],
                "credentialSubject": {
                  "name": [
                    {
                      "nameParts": [
                        {
                          "type": "GivenName",
                          "value": "ANNA"
                        },
                        {
                          "type": "GivenName",
                          "value": "NICHOLA"
                        },
                        {
                          "type": "FamilyName",
                          "value": "OTHER FORTYFOUR"
                        }
                      ]
                    }
                  ],
                  "birthDate": [
                    {
                      "value": "1960-01-01"
                    }
                  ],
                  "deviceId": [
                    {
                      "value": "a3017511-b639-46ff-ab73-66e5ab0193c9"
                    }
                  ],
                  "passport": [
                    {
                      "icaoIssuerCode": "GBR",
                      "documentNumber": "549364783",
                      "expiryDate": "2027-08-01"
                    }
                  ]
                },
                "type": [
                  "VerifiableCredential",
                  "IdentityCheckCredential"
                ],
                "evidence": [
                  {
                    "type": "IdentityCheck",
                    "txn": "biometricId",
                    "strengthScore": 4,
                    "validityScore": 3,
                    "checkDetails": [
                      {
                        "checkMethod": "vcrypt",
                        "identityCheckPolicy": "published",
                        "activityFrom": null
                      },
                      {
                        "checkMethod": "bvr",
                        "biometricVerificationProcessLevel": 3
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
    private static final String VALID_UK_PASSPORT_VC_SIGNATURE =
            "dnXc3avCGKj6XdKpGnNTgjH3lpRZotBSyzx4ttFksnaheiHExklxqGHc8ZNRdIJu0cpFyP-Dw6Bl5xO46nZCVA"; // pragma: allowlist secret

    private static final String VALID_ADDRESS_VC_BODY =
            """
                {
                  "iss": "dummyAddressComponentId",
                  "sub": "test-subject",
                  "nbf": 4070908800,
                  "exp": 4070909400,
                  "vc": {
                     "type": [
                       "VerifiableCredential",
                       "AddressCredential"
                     ],
                     "credentialSubject": {
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
                       "birthDate": [
                         {
                           "value": "1932-02-25"
                         }
                       ],
                       "address": [
                         {
                            "buildingName": "221B",
                            "streetName": "BAKER STREET",
                            "postalCode": "NW1 6XE",
                            "addressLocality": "LONDON",
                            "validFrom": "1887-01-01"
                          }
                       ]
                     }
                   },
                   "jti": "dummyJti"
                 }
                    """;

    // If we generate the signature in code it will be different each time, so we need to generate a
    // valid signature (using https://jwt.io works well) and record it here so the PACT file doesn't
    // change each time we run the tests.
    private static final String VALID_ADDRESS_VC_SIGNATURE =
            "EFfq4iMeJ9ekCYJDZS8MTqxK0semEH7HRMac9Tc69zILtxzlVmJxnrhsVSgjpMNi3osCBUhWlz3Zh-jEUB4izw"; // pragma: allowlist secret
}
