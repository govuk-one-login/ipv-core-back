package uk.gov.di.ipv.core.builduseridentity.pact;

import au.com.dius.pact.provider.junit5.HttpTestTarget;
import au.com.dius.pact.provider.junit5.PactVerificationContext;
import au.com.dius.pact.provider.junit5.PactVerificationInvocationContextProvider;
import au.com.dius.pact.provider.junitsupport.Provider;
import au.com.dius.pact.provider.junitsupport.State;
import au.com.dius.pact.provider.junitsupport.loader.PactFolder;
import org.apache.commons.codec.digest.DigestUtils;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.TestTemplate;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import uk.gov.di.ipv.core.builduseridentity.BuildUserIdentityHandler;
import uk.gov.di.ipv.core.library.cimit.exception.CiRetrievalException;
import uk.gov.di.ipv.core.library.domain.ContraIndicators;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.dto.AccessTokenMetadata;
import uk.gov.di.ipv.core.library.enums.Vot;
import uk.gov.di.ipv.core.library.exceptions.CredentialParseException;
import uk.gov.di.ipv.core.library.pacttesthelpers.LambdaHttpServer;
import uk.gov.di.ipv.core.library.pacttesthelpers.PactJwtBuilder;
import uk.gov.di.ipv.core.library.persistence.DataStore;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.VcStoreItem;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.CiMitService;
import uk.gov.di.ipv.core.library.service.CiMitUtilityService;
import uk.gov.di.ipv.core.library.service.ClientOAuthSessionDetailsService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.service.UserIdentityService;
import uk.gov.di.ipv.core.library.verifiablecredential.service.SessionCredentialsService;
import uk.gov.di.ipv.core.library.verifiablecredential.service.VerifiableCredentialService;

import java.io.IOException;
import java.text.ParseException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.CORE_VTM_CLAIM;
import static uk.gov.di.ipv.core.library.domain.CriConstants.ADDRESS_CRI;
import static uk.gov.di.ipv.core.library.domain.CriConstants.DCMAW_CRI;

@PactFolder("pacts")
@Disabled("PACT tests should not be run in build pipelines at this time")
@Provider("IpvCoreBackUserIdentityProvider")
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class BuildUserIdentityHandlerTest {

    private static final int PORT = 5050;

    private LambdaHttpServer httpServer;
    @Mock private ConfigService mockConfigService;
    @Mock private AuditService mockAuditService;
    @Mock private DataStore<IpvSessionItem> mockIpvSessionDataStore;
    @Mock private DataStore<VcStoreItem> mockVcStore;
    @Mock private DataStore<ClientOAuthSessionItem> mockOAuthSessionStore;
    @Mock private CiMitService mockCiMitService;
    @Mock private CiMitUtilityService mockCiMitUtilityService;
    @Mock private SessionCredentialsService mockSessionCredentialsService;

    @BeforeAll
    static void setupServer() {
        System.setProperty("pact.verifier.publishResults", "true");
        System.setProperty("pact.content_type.override.application/jwt", "text");
    }

    @BeforeEach
    void pactSetup(PactVerificationContext context)
            throws IOException, CiRetrievalException, ParseException, CredentialParseException {

        var userIdentityService = new UserIdentityService(mockConfigService);
        var ipvSessionService = new IpvSessionService(mockIpvSessionDataStore);
        var clientOAuthSessionDetailsService =
                new ClientOAuthSessionDetailsService(mockOAuthSessionStore, mockConfigService);

        // Configure CIMIT service to return VC and no CIs
        var jwtBuilder =
                new PactJwtBuilder(VC_HEADER, CIMIT_VC_NO_CIS_BODY, CIMIT_VC_NO_CIS_SIGNATURE);
        var cimitVc = VerifiableCredential.fromValidJwt(null, null, jwtBuilder.buildSignedJwt());
        when(mockCiMitService.getContraIndicatorsVc(
                        "dummyOAuthUserId", "dummySigninJourneyId", null))
                .thenReturn(cimitVc);

        var contraIndicators = ContraIndicators.builder().usersContraIndicators(List.of()).build();
        when(mockCiMitService.getContraIndicators(cimitVc)).thenReturn(contraIndicators);

        // Configure the config service
        when(mockConfigService.getSsmParameter(CORE_VTM_CLAIM)).thenReturn("dummyVtmClaim");

        // Configure passport and address VCs
        // 2020-01-01 00:00:00 is 1577836800 in epoch seconds
        Instant thePast = Instant.ofEpochSecond(1577836800);
        // 2099-01-01 00:00:00 is 4070908800 in epoch seconds
        Instant theFuture = Instant.ofEpochSecond(1577836800);

        List<VcStoreItem> vcs = new ArrayList<>();
        var passportVcBuilder =
                new PactJwtBuilder(
                        VC_HEADER, VALID_UK_PASSPORT_VC_BODY, VALID_UK_PASSPORT_VC_SIGNATURE);
        var addressVcBuilder =
                new PactJwtBuilder(VC_HEADER, VALID_ADDRESS_VC_BODY, VALID_ADDRESS_VC_SIGNATURE);
        var passportItem = new VcStoreItem();
        passportItem.setUserId("dummyOAuthUserId");
        passportItem.setCredential(passportVcBuilder.buildJwt());
        passportItem.setCredentialIssuer(DCMAW_CRI);
        passportItem.setDateCreated(thePast);
        passportItem.setExpirationTime(theFuture);
        vcs.add(passportItem);
        var addressItem = new VcStoreItem();
        addressItem.setUserId("dummyOAuthUserId");
        addressItem.setCredential(addressVcBuilder.buildJwt());
        addressItem.setCredentialIssuer(ADDRESS_CRI);
        addressItem.setDateCreated(thePast);
        addressItem.setExpirationTime(theFuture);
        vcs.add(addressItem);

        when(mockVcStore.getItems("dummyOAuthUserId")).thenReturn(vcs);

        var verifiableCredentialService = new VerifiableCredentialService(mockVcStore);

        // Set up the web server for the tests
        var handler =
                new BuildUserIdentityHandler(
                        userIdentityService,
                        ipvSessionService,
                        mockConfigService,
                        mockAuditService,
                        clientOAuthSessionDetailsService,
                        mockCiMitService,
                        mockCiMitUtilityService,
                        verifiableCredentialService,
                        mockSessionCredentialsService);

        httpServer = new LambdaHttpServer(handler, "/user-identity", PORT);
        httpServer.startServer();

        context.setTarget(new HttpTestTarget("localhost", PORT));
    }

    @AfterEach
    public void tearDown() {
        httpServer.stopServer();
    }

    @State("send user identity request to IPV")
    public void setAuthCode() {}

    @State("accessToken is a valid access token")
    public void setAccessToken() {
        var accessTokenMetaData = new AccessTokenMetadata();
        var ipvSession = new IpvSessionItem();
        ipvSession.setIpvSessionId("dummyIpvSessionId");
        ipvSession.setClientOAuthSessionId("dummyClientOAuthSessionId");
        ipvSession.setVot(Vot.P2);

        var oAuthSession = new ClientOAuthSessionItem();
        oAuthSession.setUserId("dummyOAuthUserId");
        oAuthSession.setClientId("dummyOAuthClientId");
        oAuthSession.setGovukSigninJourneyId("dummySigninJourneyId");
        when(mockOAuthSessionStore.getItem("dummyClientOAuthSessionId")).thenReturn(oAuthSession);
        ipvSession.setAccessTokenMetadata(accessTokenMetaData);

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

    private final String VC_HEADER =
            """
            {
              "alg": "ES256",
              "typ": "JWT"
            }
            """;

    private final String CIMIT_VC_NO_CIS_BODY =
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

    private final String CIMIT_VC_NO_CIS_SIGNATURE =
            "q9bLcKWe9K13QJoJL-f8Lz4UdhUGfzQgXPtsmu5TK5W2mP4mr7oXJjqKBAUPypnZdWza1zdKZiQpAmmVy1BW3A";

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
            "dnXc3avCGKj6XdKpGnNTgjH3lpRZotBSyzx4ttFksnaheiHExklxqGHc8ZNRdIJu0cpFyP-Dw6Bl5xO46nZCVA";

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
                       "IdentityCheckCredential"
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
            "EFfq4iMeJ9ekCYJDZS8MTqxK0semEH7HRMac9Tc69zILtxzlVmJxnrhsVSgjpMNi3osCBUhWlz3Zh-jEUB4izw";
}
