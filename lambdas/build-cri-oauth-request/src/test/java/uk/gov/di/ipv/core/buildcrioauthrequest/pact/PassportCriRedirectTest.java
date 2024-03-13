package uk.gov.di.ipv.core.buildcrioauthrequest.pact;

import au.com.dius.pact.consumer.MockServer;
import au.com.dius.pact.consumer.dsl.PactDslWithProvider;
import au.com.dius.pact.consumer.junit.MockServerConfig;
import au.com.dius.pact.consumer.junit5.PactConsumerTestExt;
import au.com.dius.pact.consumer.junit5.PactTestFor;
import au.com.dius.pact.core.model.RequestResponsePact;
import au.com.dius.pact.core.model.annotations.Pact;
import com.amazonaws.services.lambda.runtime.Context;
import com.nimbusds.jose.EncryptionMethod;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.buildcrioauthrequest.BuildCriOauthRequestHandler;
import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
import uk.gov.di.ipv.core.library.domain.JourneyRequest;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.dto.OauthCriConfig;
import uk.gov.di.ipv.core.library.exceptions.CredentialParseException;
import uk.gov.di.ipv.core.library.gpg45.Gpg45ProfileEvaluator;
import uk.gov.di.ipv.core.library.helpers.SecureTokenHelper;
import uk.gov.di.ipv.core.library.kmses256signer.KmsEs256SignerFactory;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.CriOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.ClientOAuthSessionDetailsService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.CriOAuthSessionService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.verifiablecredential.service.VerifiableCredentialService;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.COMPONENT_ID;
import static uk.gov.di.ipv.core.library.domain.CriConstants.PASSPORT_CRI;

@Disabled("PACT tests should not be run in build pipelines at this time")
@ExtendWith(PactConsumerTestExt.class)
@ExtendWith(MockitoExtension.class)
@PactTestFor(providerName = "PassportCriRedirectProvider")
@MockServerConfig(hostInterface = "localhost")
class PassportCriRedirectTest {
    @Mock private ConfigService mockConfigService;
    @Mock private KmsEs256SignerFactory mockKmsEs256SignerFactory;
    @Mock private AuditService mockAuditService;
    @Mock private IpvSessionService mockSessionService;
    @Mock private CriOAuthSessionService mockCriOAuthSessionService;
    @Mock private ClientOAuthSessionDetailsService mockClientOAuthSessionDetailsService;
    @Mock private Gpg45ProfileEvaluator mockGpg45ProfileEvaluator;
    @Mock private VerifiableCredentialService mockVerifiableCredentialService;
    @Mock private SecureTokenHelper mockSecureTokenHelper;
    @Mock private JWSSigner mockSigner;
    @Mock private Context mockContext;
    private BuildCriOauthRequestHandler underTest;

    @BeforeEach
    public void setup() {
        // Fix the secure token value
        when(mockSecureTokenHelper.generate())
                .thenReturn("ScnF4dGXthZYXS_5k85ObEoSU04W-H3qa_p6npv2ZUY");

        underTest =
                new BuildCriOauthRequestHandler(
                        mockConfigService,
                        mockKmsEs256SignerFactory,
                        mockAuditService,
                        mockSessionService,
                        mockCriOAuthSessionService,
                        mockClientOAuthSessionDetailsService,
                        mockGpg45ProfileEvaluator,
                        mockVerifiableCredentialService,
                        mockSecureTokenHelper,
                        CURRENT_TIME);
    }

    @Pact(provider = "PassportCriProvider", consumer = "IpvCoreBack")
    public RequestResponsePact validRequestReturnsHtmlPage(PactDslWithProvider builder) {
        return builder.given("c6af9ac6-7b61-11e6-9a41-93e8deadbeef is a valid authorization code")
                .given(
                        "The request JWT is signed with {\"kty\":\"EC\",\"d\":\"OXt0P05ZsQcK7eYusgIPsqZdaBCIJiW4imwUtnaAthU\",\"crv\":\"P-256\",\"x\":\"E9ZzuOoqcVU4pVB9rpmTzezjyOPRlOmPGJHKi8RSlIM\",\"y\":\"KlTMZthHZUkYz5AleTQ8jff0TJiS3q2OB9L5Fw4xA04\"}")
                .given(
                        "The request JWE is encrypted with {\"kty\":\"RSA\",\"e\":\"AQAB\",\"n\":\"vyapkvJXLwpYRJjbkQD99V2gcPEUKrO3dwjcAA9TPkLucQEZvYZvb7-wfSHxlvJlJcdS20r5PKKmqdPeW3Y4ir3WsVVeiht2iOZUreUO5O3V3o7ImvEjPS_2_ZKMHCwUf51a6WGOaDjO87OX_bluV2dp01n-E3kiIl6RmWCVywjn13fX3jsX0LMCM_bt3HofJqiYhhNymEwh39oR_D7EE5sLUii2XvpTYPa6L_uPwdKa4vRl4h4owrWEJaJifMorGcvqhCK1JOHqgknN_3cb_ns9Px6ynQCeFXvBDJy4q71clkBq_EZs5227Y1S222wXIwUYN8w5YORQe3M-pCIh1Q\"}")
                .given("The IPV Core component ID is " + DUMMY_IPV_CORE_COMPONENT_ID)
                .uponReceiving("Valid get request for CRI start")
                .path("/authorize")
                .method("get")
                .query("client_id=ipv-core")
                .matchQuery("request", REQUEST_REGEX, REQUEST_EXAMPLE)
                .willRespondWith()
                .status(200)
                .body("<html><body>Hello world</body></html>")
                .toPact();
    }

    @Test
    @PactTestFor(pactMethod = "validRequestReturnsHtmlPage")
    void handleRequest_whenCalledForPassportCriJourney_returnsAValidRedirectUrl(
            MockServer mockServer)
            throws URISyntaxException, JOSEException, IOException, CredentialParseException {
        // Arrange

        // Don't pass any VCs to the CRI
        List<VerifiableCredential> vcs = new ArrayList<>();
        when(mockVerifiableCredentialService.getVcs(DUMMY_OAUTH_USER_ID)).thenReturn(vcs);

        // Set up the passport CRI config
        when(mockConfigService.getActiveConnection(PASSPORT_CRI)).thenReturn(ACTIVE_CONFIG);

        OauthCriConfig oauthCriConfig =
                OauthCriConfig.builder()
                        .tokenUrl(new URI("http://localhost:" + mockServer.getPort() + "/token"))
                        .credentialUrl(
                                new URI(
                                        "http://localhost:"
                                                + mockServer.getPort()
                                                + "/userinfo/v2"))
                        .authorizeUrl(
                                new URI("http://localhost:" + mockServer.getPort() + "/authorize"))
                        .clientId(IPV_CORE_CLIENT_ID)
                        .signingKey(CRI_SIGNING_PRIVATE_KEY_JWK)
                        .encryptionKey(CRI_RSA_ENCRYPTION_PUBLIC_JWK)
                        .componentId(TEST_ISSUER)
                        .clientCallbackUrl(
                                URI.create("https://mock-redirect-uri.gov.uk/callback/criId"))
                        .requiresApiKey(false)
                        .requiresAdditionalEvidence(false)
                        .build();

        when(mockConfigService.getOauthCriConfigForConnection(ACTIVE_CONFIG, PASSPORT_CRI))
                .thenReturn(oauthCriConfig);
        when(mockConfigService.getSsmParameter(ConfigurationVariable.JWT_TTL_SECONDS))
                .thenReturn("900");
        when(mockConfigService.getSsmParameter(COMPONENT_ID))
                .thenReturn(DUMMY_IPV_CORE_COMPONENT_ID);

        // Set up the IPV session
        IpvSessionItem ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setClientOAuthSessionId(DUMMY_CLIENT_OAUTH_SESSION_ID);

        when(mockSessionService.getIpvSession(DUMMY_IPV_SESSION_ID)).thenReturn(ipvSessionItem);

        // Set up the OAuth session
        ClientOAuthSessionItem clientOAuthSessionItem = new ClientOAuthSessionItem();
        clientOAuthSessionItem.setUserId(DUMMY_OAUTH_USER_ID);
        clientOAuthSessionItem.setGovukSigninJourneyId("dummySigninJourneyId");

        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(
                        DUMMY_CLIENT_OAUTH_SESSION_ID))
                .thenReturn(clientOAuthSessionItem);

        // Fix the signature here as mocking out the AWSKMS class inside the real signer would be
        // painful.
        when(mockKmsEs256SignerFactory.getSigner(any())).thenReturn(mockSigner);
        when(mockSigner.sign(any(), any())).thenReturn(new Base64URL(REQUEST_JWT_SIGNATURE));
        when(mockSigner.supportedJWSAlgorithms()).thenReturn(Set.of(JWSAlgorithm.ES256));

        // Create a passport CRI journey request
        JourneyRequest journeyRequest =
                JourneyRequest.builder()
                        .ipvSessionId(DUMMY_IPV_SESSION_ID)
                        .ipAddress("127.0.0.1")
                        .journey("/journey/cri/build-oauth-request/" + PASSPORT_CRI)
                        .clientOAuthSessionId("dummyOauthSessionId")
                        .build();

        // Act
        var response = underTest.handleRequest(journeyRequest, mockContext);

        var url = ((HashMap<String, String>) response.get("cri")).get("redirectUrl");
        HTTPRequest httpRequest = new HTTPRequest(HTTPRequest.Method.GET, new URI(url));
        var criResponse = httpRequest.send();

        // Assert
        assertTrue(criResponse.getContent().contains("<html"));
        assertEquals(200, criResponse.getStatusCode());
    }

    private static final String TEST_ISSUER = "dummyPassportComponentId";
    private static final String IPV_CORE_CLIENT_ID = "ipv-core";
    private static final String DUMMY_IPV_CORE_COMPONENT_ID = "dummyIpvCoreComponentId";
    public static final String DUMMY_OAUTH_USER_ID = "dummyOAuthUserId";
    public static final String DUMMY_CLIENT_OAUTH_SESSION_ID = "dummyClientOAuthSessionId";
    public static final String DUMMY_IPV_SESSION_ID = "dummyIpvSessionId";
    private static final String ACTIVE_CONFIG = "main";

    private static final EncryptionMethod enc = EncryptionMethod.A256GCM;
    private static final Clock CURRENT_TIME =
            Clock.fixed(Instant.parse("2099-01-01T00:00:00.00Z"), ZoneOffset.UTC);
    public static final CriOAuthSessionItem CRI_OAUTH_SESSION_ITEM =
            new CriOAuthSessionItem(
                    "dummySessionId", "dummyOAuthSessionId", "dummyCriId", "dummyConnection", 900);
    private static final String CRI_SIGNING_PRIVATE_KEY_JWK =
            """
            {"kty":"EC","d":"OXt0P05ZsQcK7eYusgIPsqZdaBCIJiW4imwUtnaAthU","crv":"P-256","x":"E9ZzuOoqcVU4pVB9rpmTzezjyOPRlOmPGJHKi8RSlIM","y":"KlTMZthHZUkYz5AleTQ8jff0TJiS3q2OB9L5Fw4xA04"}
            """;
    private static final String CRI_RSA_ENCRYPTION_PUBLIC_JWK =
            """
            {"kty":"RSA","e":"AQAB","n":"vyapkvJXLwpYRJjbkQD99V2gcPEUKrO3dwjcAA9TPkLucQEZvYZvb7-wfSHxlvJlJcdS20r5PKKmqdPeW3Y4ir3WsVVeiht2iOZUreUO5O3V3o7ImvEjPS_2_ZKMHCwUf51a6WGOaDjO87OX_bluV2dp01n-E3kiIl6RmWCVywjn13fX3jsX0LMCM_bt3HofJqiYhhNymEwh39oR_D7EE5sLUii2XvpTYPa6L_uPwdKa4vRl4h4owrWEJaJifMorGcvqhCK1JOHqgknN_3cb_ns9Px6ynQCeFXvBDJy4q71clkBq_EZs5227Y1S222wXIwUYN8w5YORQe3M-pCIh1Q"}
            """;
    // This example was copied from the test output and is assumed to be correct - if it works on
    // the provider side then
    // it should be OK.
    private static final String REQUEST_EXAMPLE =
            "eyJjdHkiOiJKV1QiLCJlbmMiOiJBMjU2R0NNIiwiYWxnIjoiUlNBLU9BRVAtMjU2In0.nJhIo04rpfVaHVq6hYBZIxwhS-IDuYgEtANM_mBqm3eItRjPNCWrdywDMueMP5Jdet8j0CUbKYzDJoUYpPbiruTR645lWisE3NBKh3JZbBJlkZtCwZrBo_X5mK6EryiXUEF3zcPul2IbgbLYppXLnogoZPSSIAuOo5CCIGs-cpwMgnfVFpdEZzC_DRzgMwDy--TesGeHjGf8Iuz4vaqXs-Nc997pSB7wX6i-v6wRZfdz-L7j-I5KBABKSIDONQp7N4QBvxYg4Bz80yZFzp0bjJzgmXnh0gdXX1-oYOoyvmZmFxf04aV_wO-1bUTRORsMsFObaisYJMjC6pqGwOSmGw.AAAAAAAAAAAAAAAA.q94KDSg4KgdIJ4-Y7MLMcT4jSaJV4Ukdnsu_yCB8fL-TI_sRYy-YMTuMDm0uQ1-9LCWc0PXeKgkjGEWxxFpiUbyn5B9K4URACfaeiCnyCvbX93v-s5fxQZLfZS9iO2Tnw6Awnxffgmol-de1h3SvXtNojO1cbbO6VdCGPuBeDVgzAazpCYqz9wemu30ay-K3mFgB3JIRW-WMQpx9w2GCSM9EvtGEM4Z6yTvY1TUy7_uEABBrDmgOIuYEtmCIG0osGuhLgj02i1CZojS3M8AYk9n4eW725BSzxSO8D0GOjFZkyvdvTLZx0YLCPIxgvVlkfJqIIPSi0pJDFe4Zx6LXbkwNY0EqGBfDq5ftpo7Xwid3MB9DDX6RX-UGGzQGUsUVnauKlr8WvEBkC7h4AR8f6n5RBq4SlhfqoUeR0IO5NugN1TkdexplnSuIsfEnnqzpEN7wpXSe5XbWgHBuBWy53fP56UN9x6ZJz3KLVcEYRuGltshlqS3oN10aFXT9l8UGuzKuRsT53vxKibuL4BEU6l772pKytT1wnE_FlL8L_ujGmEv0Sb-iZ-qLoliUjrOxYkTzxveDHmPrdy_EpfwCZNdYdeFCFOhMG3BDptxP-Qv-JYKhBucwcXkNc5GL8iTBeHeXdhXBg2u4Iy-4dOfGKh3qOsve8byR6IJbCsgfSKXpBd9kp8AjyrTaGeSl1WjqrrPZyFdeWek6VuW_nCX_Ygt4kDOIqvfdX7kyy_1ik8tqqZ0aMPFRhLdLcF_-pdBiAR5yVSmHsvZITPMevqtSMzEEpr3xPZ8N93B6qOq29XRtcyQyl81GEAeQGFultj2F1LipNjAR-Z5YkQjR2vdyQbP7r5X30Oold9WPoh5hLHOZYD3Mt81TFxFJLhx6SawTAoZ-5j0mJQ.oHDJerh_Ayq9LFhpK0HQvg";
    private static final String REQUEST_HEADER = REQUEST_EXAMPLE.split("\\.")[0];
    private static final String REQUEST_INITIALIZATION_VECTOR = REQUEST_EXAMPLE.split("\\.")[2];
    private static final String REQUEST_CIPHER_TEXT = REQUEST_EXAMPLE.split("\\.")[3];
    private static final String REQUEST_AUTHENTICATION_TAG = REQUEST_EXAMPLE.split("\\.")[4];
    // Create a regex that skips the second part of the JWE as we can't make the key padding
    // deterministic
    private static final String REQUEST_REGEX =
            "^"
                    + REQUEST_HEADER
                    + "\\..+\\."
                    + REQUEST_INITIALIZATION_VECTOR
                    + "."
                    + REQUEST_CIPHER_TEXT
                    + "."
                    + REQUEST_AUTHENTICATION_TAG
                    + "$";

    // This signature was generated by copying the SignedJWT contents from signEncryptJar() during
    // debugging and then
    // using JWT.io with CRI_SIGNING_PRIVATE_KEY_JWK
    private static final String REQUEST_JWT_SIGNATURE =
            "VqWmPBQqRbfmQTntvQHk-LCNdWrnzM0mFCcbS7vdtcTZOd3uECYKpGsTCAJf5S3rh5WQh4FiWPZdeTE9GKwtlg";
}
