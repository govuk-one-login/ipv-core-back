package uk.gov.di.ipv.core.issueclientaccesstoken.pact;

import au.com.dius.pact.provider.junit5.HttpTestTarget;
import au.com.dius.pact.provider.junit5.PactVerificationContext;
import au.com.dius.pact.provider.junit5.PactVerificationInvocationContextProvider;
import au.com.dius.pact.provider.junitsupport.Provider;
import au.com.dius.pact.provider.junitsupport.State;
import au.com.dius.pact.provider.junitsupport.loader.PactFolder;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
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
import uk.gov.di.ipv.core.issueclientaccesstoken.IssueClientAccessTokenHandler;
import uk.gov.di.ipv.core.issueclientaccesstoken.persistance.item.ClientAuthJwtIdItem;
import uk.gov.di.ipv.core.issueclientaccesstoken.service.AccessTokenService;
import uk.gov.di.ipv.core.issueclientaccesstoken.service.ClientAuthJwtIdService;
import uk.gov.di.ipv.core.issueclientaccesstoken.validation.TokenRequestValidator;
import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
import uk.gov.di.ipv.core.library.dto.AuthorizationCodeMetadata;
import uk.gov.di.ipv.core.library.pacttesthelpers.Injector;
import uk.gov.di.ipv.core.library.pacttesthelpers.MockHttpServer;
import uk.gov.di.ipv.core.library.persistence.DataStore;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.ClientOAuthSessionDetailsService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;

import java.io.IOException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.ECPrivateKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.COMPONENT_ID;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.MAX_ALLOWED_AUTH_CLIENT_TTL;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.PUBLIC_KEY_MATERIAL_FOR_CORE_TO_VERIFY;

@PactFolder("pacts")
@Disabled("PACT tests should not be run in build pipelines at this time")
@Provider("IpvCoreBack")
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
public class IssueClientAccessTokenHandlerTest {

    private static final int PORT = 5050;

    @Mock private ConfigService configService;
    @Mock private DataStore<IpvSessionItem> ipvSessionDataStore;
    @Mock private DataStore<ClientOAuthSessionItem> oAuthDataStore;
    @Mock private DataStore<ClientAuthJwtIdItem> jwtIdStore;

    private ClientAuthJwtIdItem jwtIdItem;

    private static final String CRI_SIGNING_PRIVATE_KEY_JWK =
            """
            {"kty":"EC","d":"OXt0P05ZsQcK7eYusgIPsqZdaBCIJiW4imwUtnaAthU","crv":"P-256","x":"E9ZzuOoqcVU4pVB9rpmTzezjyOPRlOmPGJHKi8RSlIM","y":"KlTMZthHZUkYz5AleTQ8jff0TJiS3q2OB9L5Fw4xA04"}
            """;

    @BeforeAll
    static void setupServer() {
        System.setProperty("pact.verifier.publishResults", "true");
        System.setProperty("pact.content_type.override.application/jwt", "text");
    }

    @BeforeEach
    void pactSetup(PactVerificationContext context)
            throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, JOSEException {

        var accessTokenService = new AccessTokenService(configService);
        var sessionService = new IpvSessionService(ipvSessionDataStore, configService);
        var clientOAuthSessionService =
                new ClientOAuthSessionDetailsService(oAuthDataStore, configService);
        var clientAuthJwtIdService = new ClientAuthJwtIdService(configService, jwtIdStore);
        var tokenRequestValidator =
                new TokenRequestValidator(configService, clientAuthJwtIdService);
        var ipvSessionItem = new IpvSessionItem();
        var clientOAuthSessionItem = new ClientOAuthSessionItem();
        var authorizationCodeMetadata = new AuthorizationCodeMetadata();
        authorizationCodeMetadata.setCreationDateTime(
                "2024-02-01T00:00:00.000Z"); // Ensure that the metadata isn't flagged as expired
        authorizationCodeMetadata.setRedirectUrl(
                "https://identity.staging.account.gov.uk/credential-issuer/callback?id=ukPassport");

        when(configService.getSsmParameter(COMPONENT_ID)).thenReturn("dummyIpvComponentId");
        when(configService.getSsmParameter(PUBLIC_KEY_MATERIAL_FOR_CORE_TO_VERIFY, "orch"))
                .thenReturn(CRI_SIGNING_PRIVATE_KEY_JWK);
        when(configService.getSsmParameter(MAX_ALLOWED_AUTH_CLIENT_TTL))
                .thenReturn("3153600000"); // 100 years
        when(configService.getSsmParameter(ConfigurationVariable.AUTH_CODE_EXPIRY_SECONDS))
                .thenReturn("3153600000"); // 100 years
        when(configService.getBearerAccessTokenTtl()).thenReturn(3153600000L); // 100 years
        when(ipvSessionDataStore.getItemByIndex(
                        "authorizationCode", DigestUtils.sha256Hex("dummyAuthCode")))
                .thenReturn(ipvSessionItem);
        ipvSessionItem.setClientOAuthSessionId("dummyOuthSessionId");
        when(oAuthDataStore.getItem("dummyOuthSessionId")).thenReturn(clientOAuthSessionItem);
        ipvSessionItem.setAuthorizationCodeMetadata(authorizationCodeMetadata);
        // when(jwtIdStore.getItem("ScnF4dGXthZYXS_5k85ObEoSU04W-H3qa_p6npv2ZUY",
        // false)).thenReturn(jwtIdItem);

        // qq:DCC is this needed?
        KeyFactory kf = KeyFactory.getInstance("EC");
        EncodedKeySpec privateKeySpec =
                new PKCS8EncodedKeySpec(
                        Base64.getDecoder()
                                .decode(
                                        "MEECAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQcEJzAlAgEBBCBYNBSda5ttN9Wu4Do4"
                                                + "gLV1xaks+DB5n6ity2MvBlzDUw=="));
        JWSSigner signer = new ECDSASigner((ECPrivateKey) kf.generatePrivate(privateKeySpec));

        Injector tokenHandlerInjector =
                new Injector(
                        new IssueClientAccessTokenHandler(
                                accessTokenService,
                                sessionService,
                                configService,
                                clientOAuthSessionService,
                                tokenRequestValidator),
                        "/token",
                        "/");

        MockHttpServer.startServer(new ArrayList<>(List.of(tokenHandlerInjector)), PORT, signer);

        context.setTarget(new HttpTestTarget("localhost", PORT));
    }

    @AfterEach
    public void tearDown() {
        MockHttpServer.stopServer();
    }

    @State("dummyAuthCode is a valid authorization code")
    public void setAuthCode() {}

    @State("dummyApiKey is a valid api key")
    public void setApiKey() {}

    @State("dummyInvalidAuthCode is an invalid authorization code")
    public void dontSetAuthCode() {}

    @State("dummyPassportComponentId is the passport CRI component ID")
    public void setComponentId() {}

    @State("Passport CRI uses CORE_BACK_SIGNING_PRIVATE_KEY_JWK to validate core signatures")
    public void setSigningKey() {}

    @TestTemplate
    @ExtendWith(PactVerificationInvocationContextProvider.class)
    void testMethod(PactVerificationContext context) {
        context.verifyInteraction();
    }
}
