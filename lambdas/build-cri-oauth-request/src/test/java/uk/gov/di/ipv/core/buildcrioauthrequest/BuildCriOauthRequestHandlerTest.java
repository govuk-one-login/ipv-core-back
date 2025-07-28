package uk.gov.di.ipv.core.buildcrioauthrequest;

import com.amazonaws.services.lambda.runtime.Context;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWEObject;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSADecrypter;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.apache.commons.collections4.ListUtils;
import org.apache.hc.core5.http.NameValuePair;
import org.apache.hc.core5.net.URIBuilder;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.ArgumentCaptor;
import org.mockito.InOrder;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.junit.jupiter.MockitoExtension;
import software.amazon.awssdk.http.HttpStatusCode;
import uk.gov.di.ipv.core.buildcrioauthrequest.domain.CriResponse;
import uk.gov.di.ipv.core.buildcrioauthrequest.domain.SharedClaims;
import uk.gov.di.ipv.core.buildcrioauthrequest.helpers.SharedClaimsHelper;
import uk.gov.di.ipv.core.library.auditing.AuditEvent;
import uk.gov.di.ipv.core.library.auditing.AuditEventTypes;
import uk.gov.di.ipv.core.library.domain.CriJourneyRequest;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.EvidenceRequest;
import uk.gov.di.ipv.core.library.domain.JourneyErrorResponse;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.dto.OauthCriConfig;
import uk.gov.di.ipv.core.library.enums.Vot;
import uk.gov.di.ipv.core.library.gpg45.Gpg45ProfileEvaluator;
import uk.gov.di.ipv.core.library.gpg45.Gpg45Scores;
import uk.gov.di.ipv.core.library.helpers.SecureTokenHelper;
import uk.gov.di.ipv.core.library.oauthkeyservice.OAuthKeyService;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.ClientOAuthSessionDetailsService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.CriOAuthSessionService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.signing.LocalECDSASigner;
import uk.gov.di.ipv.core.library.signing.SignerFactory;
import uk.gov.di.ipv.core.library.testhelpers.unit.LogCollector;
import uk.gov.di.ipv.core.library.useridentity.service.UserIdentityService;
import uk.gov.di.ipv.core.library.verifiablecredential.helpers.VcHelper;
import uk.gov.di.ipv.core.library.verifiablecredential.service.SessionCredentialsService;

import java.net.URI;
import java.net.URISyntaxException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.text.ParseException;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.StringContains.containsString;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.COMPONENT_ID;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.CREDENTIAL_ISSUER_SHARED_ATTRIBUTES;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.JWT_TTL_SECONDS;
import static uk.gov.di.ipv.core.library.domain.Cri.ADDRESS;
import static uk.gov.di.ipv.core.library.domain.Cri.CLAIMED_IDENTITY;
import static uk.gov.di.ipv.core.library.domain.Cri.DCMAW;
import static uk.gov.di.ipv.core.library.domain.Cri.DWP_KBV;
import static uk.gov.di.ipv.core.library.domain.Cri.EXPERIAN_FRAUD;
import static uk.gov.di.ipv.core.library.domain.Cri.F2F;
import static uk.gov.di.ipv.core.library.domain.Cri.PASSPORT;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.CREDENTIAL_ATTRIBUTES_1;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.CREDENTIAL_ATTRIBUTES_2;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.CREDENTIAL_ATTRIBUTES_3;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.EC_PRIVATE_KEY_JWK;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.RSA_ENCRYPTION_PRIVATE_KEY;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.RSA_ENCRYPTION_PUBLIC_JWK;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.TEST_EC_PUBLIC_JWK;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcDcmawAsyncDrivingPermitDva;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcDcmawAsyncPassport;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcDcmawDrivingPermitDvaM1b;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcDcmawPassport;
import static uk.gov.di.ipv.core.library.helpers.VerifiableCredentialGenerator.generateVerifiableCredential;
import static uk.gov.di.ipv.core.library.helpers.VerifiableCredentialGenerator.vcClaimFailedWithCis;

@ExtendWith(MockitoExtension.class)
class BuildCriOauthRequestHandlerTest {

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final String CRI_TOKEN_URL = "http://www.example.com";
    private static final String CRI_CREDENTIAL_URL = "http://www.example.com/credential";
    private static final String CRI_AUTHORIZE_URL = "http://www.example.com/authorize";
    private static final String IPV_ISSUER = "http://www.example.com/issuer";
    private static final String ADDRESS_ISSUER = "http://www.example.com/address/issuer";
    private static final String IPV_CLIENT_ID = "ipv-core";
    private static final String SESSION_ID = "the-session-id";
    private static final String TEST_USER_ID = "test-user-id";
    private static final String TEST_IP_ADDRESS = "192.168.1.100";
    private static final String TEST_LANGUAGE = "en";
    private static final String JOURNEY_BASE_URL = "/journey/cri/build-oauth-request/%s";
    private static final String TEST_EMAIL_ADDRESS = "test@test.com";
    private static final String CONTEXT = "context";
    private static final String TEST_CONTEXT = "test_context";
    private static final String CRI_WITH_CONTEXT =
            String.format("%s?%s=%s", CLAIMED_IDENTITY.getId(), CONTEXT, TEST_CONTEXT);
    private static final String EVIDENCE_REQUEST = "evidenceRequest";
    private static final String EVIDENCE_REQUESTED = "evidence_requested";
    private static final EvidenceRequest TEST_EVIDENCE_REQUESTED =
            new EvidenceRequest("gpg45", 2, null, null);
    private static String CRI_WITH_EVIDENCE_REQUEST;
    private static String CRI_WITH_CONTEXT_AND_EVIDENCE_REQUEST;

    private static final String TEST_CLIENT_OAUTH_SESSION_ID =
            SecureTokenHelper.getInstance().generate();
    public static final String MAIN_CONNECTION = "main";

    public static final SharedClaims TEST_SHARED_CLAIMS = new SharedClaims();

    @Mock private Context context;
    @Mock private ConfigService configService;
    @Mock private UserIdentityService userIdentityService;
    @Mock private AuditService mockAuditService;
    @Mock private IpvSessionService mockIpvSessionService;
    @Mock private CriOAuthSessionService mockCriOAuthSessionService;
    @Mock private ClientOAuthSessionDetailsService mockClientOAuthSessionDetailsService;
    @Mock private Gpg45ProfileEvaluator mockGpg45ProfileEvaluator;
    @Mock private SessionCredentialsService mockSessionCredentialService;
    @Mock private OAuthKeyService mockOauthKeyService;
    @Mock private MockedStatic<SharedClaimsHelper> mockSharedClaimsHelper;
    @Mock private MockedStatic<VcHelper> mockVcHelper;
    @Mock private SignerFactory mockSignerFactory;
    @InjectMocks private BuildCriOauthRequestHandler buildCriOauthRequestHandler;

    private OauthCriConfig oauthCriConfig;
    private ClientOAuthSessionItem clientOAuthSessionItem;
    private final IpvSessionItem ipvSessionItem = new IpvSessionItem();

    @BeforeAll
    static void setUpAll() throws JsonProcessingException {
        CRI_WITH_EVIDENCE_REQUEST =
                String.format(
                        "%s?%s=%s",
                        CLAIMED_IDENTITY.getId(),
                        EVIDENCE_REQUEST,
                        TEST_EVIDENCE_REQUESTED.toBase64());
        CRI_WITH_CONTEXT_AND_EVIDENCE_REQUEST =
                String.format(
                        "%s?%s=%s&%s=%s",
                        CLAIMED_IDENTITY.getId(),
                        CONTEXT,
                        TEST_CONTEXT,
                        EVIDENCE_REQUEST,
                        TEST_EVIDENCE_REQUESTED.toBase64());
    }

    @BeforeEach
    void setUp() throws URISyntaxException {
        oauthCriConfig =
                OauthCriConfig.builder()
                        .tokenUrl(new URI(CRI_TOKEN_URL))
                        .credentialUrl(new URI(CRI_CREDENTIAL_URL))
                        .authorizeUrl(new URI(CRI_AUTHORIZE_URL))
                        .clientId(IPV_CLIENT_ID)
                        .signingKey("{}")
                        .encryptionKey(RSA_ENCRYPTION_PUBLIC_JWK)
                        .componentId("http://www.example.com/audience")
                        .clientCallbackUrl(URI.create("http://www.example.com/callback/criId"))
                        .requiresApiKey(true)
                        .requiresAdditionalEvidence(false)
                        .build();

        clientOAuthSessionItem =
                ClientOAuthSessionItem.builder()
                        .clientOAuthSessionId(TEST_CLIENT_OAUTH_SESSION_ID)
                        .state("test-state")
                        .responseType("code")
                        .redirectUri("https://example.com/redirect")
                        .govukSigninJourneyId("test-journey-id")
                        .userId(TEST_USER_ID)
                        .clientId("test-client")
                        .vtr(List.of("P2"))
                        .build();

        ipvSessionItem.setIpvSessionId(SESSION_ID);
        ipvSessionItem.setClientOAuthSessionId(TEST_CLIENT_OAUTH_SESSION_ID);
        ipvSessionItem.setEmailAddress(TEST_EMAIL_ADDRESS);
        ipvSessionItem.setVot(Vot.P0);

        mockSharedClaimsHelper
                .when(() -> SharedClaimsHelper.generateSharedClaims(any(), any(), any(), any()))
                .thenReturn(TEST_SHARED_CLAIMS);
    }

    @AfterEach
    void checkAuditEventWait() {
        InOrder auditInOrder = inOrder(mockAuditService);
        auditInOrder.verify(mockAuditService).awaitAuditEvents();
        auditInOrder.verifyNoMoreInteractions();
    }

    @Test
    void shouldReceive400ResponseCodeIfCredentialIssuerNotPresent() throws JsonProcessingException {
        // Arrange
        var input =
                CriJourneyRequest.builder()
                        .ipvSessionId("aSessionId")
                        .ipAddress(TEST_IP_ADDRESS)
                        .language(TEST_LANGUAGE)
                        .journey("nope")
                        .build();

        // Act
        var response = handleRequest(input, context);

        // Assert
        assertErrorResponse(
                HttpStatusCode.BAD_REQUEST, response, ErrorResponse.INVALID_CREDENTIAL_ISSUER_ID);
    }

    @Test
    void shouldReceive400ResponseCodeIfCredentialIssuerNotInPermittedSet()
            throws JsonProcessingException {
        // Arrange
        CriJourneyRequest input =
                CriJourneyRequest.builder()
                        .ipvSessionId("aSessionId")
                        .ipAddress(TEST_IP_ADDRESS)
                        .language(TEST_LANGUAGE)
                        .journey(String.format(JOURNEY_BASE_URL, "bad"))
                        .build();

        // Act
        var response = handleRequest(input, context);

        // Assert
        assertErrorResponse(
                HttpStatusCode.BAD_REQUEST, response, ErrorResponse.INVALID_CREDENTIAL_ISSUER_ID);
    }

    @Test
    void shouldReceive200ResponseCodeAndReturnCredentialIssuerResponseWithoutResponseTypeParam()
            throws Exception {
        // Arrange
        when(mockOauthKeyService.getEncryptionKey(oauthCriConfig))
                .thenReturn(RSAKey.parse(RSA_ENCRYPTION_PUBLIC_JWK));
        when(mockOauthKeyService.getEncryptionKey(oauthCriConfig))
                .thenReturn(RSAKey.parse(RSA_ENCRYPTION_PUBLIC_JWK));
        when(configService.getActiveConnection(PASSPORT)).thenReturn(MAIN_CONNECTION);
        when(configService.getOauthCriConfigForConnection(MAIN_CONNECTION, PASSPORT))
                .thenReturn(oauthCriConfig);
        when(configService.getParameter(CREDENTIAL_ISSUER_SHARED_ATTRIBUTES, PASSPORT.getId()))
                .thenReturn(null);
        when(configService.getLongParameter(JWT_TTL_SECONDS)).thenReturn(900L);
        when(configService.getParameter(COMPONENT_ID)).thenReturn(IPV_ISSUER);
        when(mockIpvSessionService.getIpvSession(SESSION_ID)).thenReturn(ipvSessionItem);
        mockVcHelper.when(() -> VcHelper.isSuccessfulVc(any())).thenReturn(true, true);
        List<VerifiableCredential> vcs =
                List.of(
                        generateVerifiableCredential(
                                TEST_USER_ID,
                                ADDRESS,
                                vcClaimFailedWithCis(CREDENTIAL_ATTRIBUTES_1),
                                IPV_ISSUER),
                        generateVerifiableCredential(
                                TEST_USER_ID,
                                ADDRESS,
                                vcClaimFailedWithCis(CREDENTIAL_ATTRIBUTES_2),
                                IPV_ISSUER));
        when(mockSessionCredentialService.getCredentials(SESSION_ID, TEST_USER_ID)).thenReturn(vcs);
        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(mockSignerFactory.getSigner())
                .thenReturn(new LocalECDSASigner(getSigningPrivateKey()));

        CriJourneyRequest input =
                CriJourneyRequest.builder()
                        .ipvSessionId(SESSION_ID)
                        .ipAddress(TEST_IP_ADDRESS)
                        .language(TEST_LANGUAGE)
                        .journey(String.format(JOURNEY_BASE_URL, PASSPORT.getId()))
                        .build();

        // Act
        var responseJson = handleRequest(input, context);

        // Assert
        CriResponse response = OBJECT_MAPPER.readValue(responseJson, CriResponse.class);

        URIBuilder redirectUri = new URIBuilder(response.getCri().getRedirectUrl());
        List<NameValuePair> queryParams = redirectUri.getQueryParams();

        assertEquals(PASSPORT.getId(), response.getCri().getId());

        Optional<NameValuePair> client_id =
                queryParams.stream()
                        .filter(param -> param.getName().equals("client_id"))
                        .findFirst();
        assertTrue(client_id.isPresent());
        assertEquals(IPV_CLIENT_ID, client_id.get().getValue());

        Optional<NameValuePair> response_type =
                queryParams.stream()
                        .filter(param -> param.getName().equals("response_type"))
                        .findFirst();
        assertFalse(response_type.isPresent());

        Optional<NameValuePair> request =
                queryParams.stream().filter(param -> param.getName().equals("request")).findFirst();
        assertTrue(request.isPresent());
        JWEObject jweObject = JWEObject.parse(request.get().getValue());
        jweObject.decrypt(new RSADecrypter(getEncryptionPrivateKey()));
        assertSharedClaimsJWTIsValid(jweObject.getPayload().toString());

        assertEquals(CRI_AUTHORIZE_URL, redirectUri.removeQuery().build().toString());

        ArgumentCaptor<AuditEvent> auditEventCaptor = ArgumentCaptor.forClass(AuditEvent.class);
        verify(mockAuditService).sendAuditEvent(auditEventCaptor.capture());
        assertEquals(
                AuditEventTypes.IPV_REDIRECT_TO_CRI, auditEventCaptor.getValue().getEventName());
        verify(mockIpvSessionService, times(1)).updateIpvSession(any());
        verify(mockCriOAuthSessionService, times(1))
                .persistCriOAuthSession(any(), any(), any(), eq(MAIN_CONNECTION));
        verify(mockClientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());
    }

    @Test
    void
            shouldReceive200ResponseCodeAndReturnCredentialIssuerResponseWithoutResponseTypeParamForAllVCsAreNotSuccess()
                    throws Exception {
        // Arrange
        when(mockOauthKeyService.getEncryptionKey(oauthCriConfig))
                .thenReturn(RSAKey.parse(RSA_ENCRYPTION_PUBLIC_JWK));
        when(configService.getActiveConnection(PASSPORT)).thenReturn(MAIN_CONNECTION);
        when(configService.getOauthCriConfigForConnection(MAIN_CONNECTION, PASSPORT))
                .thenReturn(oauthCriConfig);
        when(configService.getParameter(CREDENTIAL_ISSUER_SHARED_ATTRIBUTES, PASSPORT.getId()))
                .thenReturn(null);
        when(configService.getLongParameter(JWT_TTL_SECONDS)).thenReturn(900L);
        when(configService.getParameter(COMPONENT_ID)).thenReturn(IPV_ISSUER);
        when(mockIpvSessionService.getIpvSession(SESSION_ID)).thenReturn(ipvSessionItem);
        mockVcHelper.when(() -> VcHelper.isSuccessfulVc(any())).thenReturn(false, false);

        when(mockSessionCredentialService.getCredentials(SESSION_ID, TEST_USER_ID))
                .thenReturn(
                        List.of(
                                generateVerifiableCredential(
                                        TEST_USER_ID,
                                        ADDRESS,
                                        vcClaimFailedWithCis(CREDENTIAL_ATTRIBUTES_1),
                                        IPV_ISSUER),
                                generateVerifiableCredential(
                                        TEST_USER_ID,
                                        ADDRESS,
                                        vcClaimFailedWithCis(CREDENTIAL_ATTRIBUTES_2),
                                        IPV_ISSUER)));

        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(mockSignerFactory.getSigner())
                .thenReturn(new LocalECDSASigner(getSigningPrivateKey()));

        CriJourneyRequest input =
                CriJourneyRequest.builder()
                        .ipvSessionId(SESSION_ID)
                        .ipAddress(TEST_IP_ADDRESS)
                        .language(TEST_LANGUAGE)
                        .journey(String.format(JOURNEY_BASE_URL, PASSPORT.getId()))
                        .build();

        // Act
        var responseJson = handleRequest(input, context);

        // Assert
        CriResponse response = OBJECT_MAPPER.readValue(responseJson, CriResponse.class);

        URIBuilder redirectUri = new URIBuilder(response.getCri().getRedirectUrl());
        List<NameValuePair> queryParams = redirectUri.getQueryParams();

        assertEquals(PASSPORT.getId(), response.getCri().getId());

        Optional<NameValuePair> client_id =
                queryParams.stream()
                        .filter(param -> param.getName().equals("client_id"))
                        .findFirst();
        assertTrue(client_id.isPresent());
        assertEquals(IPV_CLIENT_ID, client_id.get().getValue());

        Optional<NameValuePair> response_type =
                queryParams.stream()
                        .filter(param -> param.getName().equals("response_type"))
                        .findFirst();
        assertFalse(response_type.isPresent());

        Optional<NameValuePair> request =
                queryParams.stream().filter(param -> param.getName().equals("request")).findFirst();
        assertTrue(request.isPresent());
        JWEObject jweObject = JWEObject.parse(request.get().getValue());
        jweObject.decrypt(new RSADecrypter(getEncryptionPrivateKey()));
        assertSharedClaimsJWTIsValid(jweObject.getPayload().toString());

        assertEquals(CRI_AUTHORIZE_URL, redirectUri.removeQuery().build().toString());

        ArgumentCaptor<AuditEvent> auditEventCaptor = ArgumentCaptor.forClass(AuditEvent.class);
        verify(mockAuditService).sendAuditEvent(auditEventCaptor.capture());
        assertEquals(
                AuditEventTypes.IPV_REDIRECT_TO_CRI, auditEventCaptor.getValue().getEventName());
        verify(mockIpvSessionService, times(1)).updateIpvSession(any());
        verify(mockCriOAuthSessionService, times(1))
                .persistCriOAuthSession(any(), any(), any(), eq(MAIN_CONNECTION));
        verify(mockClientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());
    }

    @Test
    void
            shouldReceive200ResponseCodeAndReturnCredentialIssuerResponseWithFullUrlJourneyAndWithoutResponseTypeParam()
                    throws Exception {
        // Arrange
        when(mockOauthKeyService.getEncryptionKey(oauthCriConfig))
                .thenReturn(RSAKey.parse(RSA_ENCRYPTION_PUBLIC_JWK));
        when(configService.getActiveConnection(PASSPORT)).thenReturn(MAIN_CONNECTION);
        when(configService.getOauthCriConfigForConnection(MAIN_CONNECTION, PASSPORT))
                .thenReturn(oauthCriConfig);
        when(configService.getParameter(CREDENTIAL_ISSUER_SHARED_ATTRIBUTES, PASSPORT.getId()))
                .thenReturn(null);
        when(configService.getLongParameter(JWT_TTL_SECONDS)).thenReturn(900L);
        when(configService.getParameter(COMPONENT_ID)).thenReturn(IPV_ISSUER);
        when(mockIpvSessionService.getIpvSession(SESSION_ID)).thenReturn(ipvSessionItem);
        mockVcHelper.when(() -> VcHelper.isSuccessfulVc(any())).thenReturn(true, true);
        when(mockSessionCredentialService.getCredentials(any(), any()))
                .thenReturn(
                        List.of(
                                generateVerifiableCredential(
                                        TEST_USER_ID,
                                        ADDRESS,
                                        vcClaimFailedWithCis(CREDENTIAL_ATTRIBUTES_1),
                                        IPV_ISSUER),
                                generateVerifiableCredential(
                                        TEST_USER_ID,
                                        ADDRESS,
                                        vcClaimFailedWithCis(CREDENTIAL_ATTRIBUTES_2),
                                        IPV_ISSUER)));
        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(mockSignerFactory.getSigner())
                .thenReturn(new LocalECDSASigner(getSigningPrivateKey()));

        CriJourneyRequest input =
                CriJourneyRequest.builder()
                        .ipvSessionId(SESSION_ID)
                        .ipAddress(TEST_IP_ADDRESS)
                        .language(TEST_LANGUAGE)
                        .journey(String.format(JOURNEY_BASE_URL, PASSPORT.getId()))
                        .build();

        // Act
        var responseJson = handleRequest(input, context);

        // Assert
        CriResponse response = OBJECT_MAPPER.readValue(responseJson, CriResponse.class);

        URIBuilder redirectUri = new URIBuilder(response.getCri().getRedirectUrl());
        List<NameValuePair> queryParams = redirectUri.getQueryParams();

        assertEquals(PASSPORT.getId(), response.getCri().getId());

        Optional<NameValuePair> client_id =
                queryParams.stream()
                        .filter(param -> param.getName().equals("client_id"))
                        .findFirst();
        assertTrue(client_id.isPresent());
        assertEquals(IPV_CLIENT_ID, client_id.get().getValue());

        Optional<NameValuePair> response_type =
                queryParams.stream()
                        .filter(param -> param.getName().equals("response_type"))
                        .findFirst();
        assertFalse(response_type.isPresent());

        Optional<NameValuePair> request =
                queryParams.stream().filter(param -> param.getName().equals("request")).findFirst();
        assertTrue(request.isPresent());
        JWEObject jweObject = JWEObject.parse(request.get().getValue());
        jweObject.decrypt(new RSADecrypter(getEncryptionPrivateKey()));
        assertSharedClaimsJWTIsValid(jweObject.getPayload().toString());

        assertEquals(CRI_AUTHORIZE_URL, redirectUri.removeQuery().build().toString());

        ArgumentCaptor<AuditEvent> auditEventCaptor = ArgumentCaptor.forClass(AuditEvent.class);
        verify(mockAuditService).sendAuditEvent(auditEventCaptor.capture());
        assertEquals(
                AuditEventTypes.IPV_REDIRECT_TO_CRI, auditEventCaptor.getValue().getEventName());
        verify(mockSessionCredentialService).getCredentials(SESSION_ID, TEST_USER_ID);
        verify(mockIpvSessionService, times(1)).updateIpvSession(any());
        verify(mockCriOAuthSessionService, times(1))
                .persistCriOAuthSession(any(), any(), any(), eq(MAIN_CONNECTION));
        verify(mockClientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());
    }

    @Test
    void
            shouldReceive200ResponseCodeAndReturnCredentialIssuerResponseWithoutBaseJourneyUrlAndResponseTypeParam()
                    throws Exception {
        // Arrange
        when(mockOauthKeyService.getEncryptionKey(oauthCriConfig))
                .thenReturn(RSAKey.parse(RSA_ENCRYPTION_PUBLIC_JWK));
        when(configService.getActiveConnection(PASSPORT)).thenReturn(MAIN_CONNECTION);
        when(configService.getOauthCriConfigForConnection(MAIN_CONNECTION, PASSPORT))
                .thenReturn(oauthCriConfig);
        when(configService.getParameter(CREDENTIAL_ISSUER_SHARED_ATTRIBUTES, PASSPORT.getId()))
                .thenReturn(null);
        when(configService.getLongParameter(JWT_TTL_SECONDS)).thenReturn(900L);
        when(configService.getParameter(COMPONENT_ID)).thenReturn(IPV_ISSUER);
        when(mockIpvSessionService.getIpvSession(SESSION_ID)).thenReturn(ipvSessionItem);
        mockVcHelper.when(() -> VcHelper.isSuccessfulVc(any())).thenReturn(true, true);
        when(mockSessionCredentialService.getCredentials(SESSION_ID, TEST_USER_ID))
                .thenReturn(
                        List.of(
                                generateVerifiableCredential(
                                        TEST_USER_ID,
                                        ADDRESS,
                                        vcClaimFailedWithCis(CREDENTIAL_ATTRIBUTES_1),
                                        IPV_ISSUER),
                                generateVerifiableCredential(
                                        TEST_USER_ID,
                                        ADDRESS,
                                        vcClaimFailedWithCis(CREDENTIAL_ATTRIBUTES_2),
                                        IPV_ISSUER)));
        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(mockSignerFactory.getSigner())
                .thenReturn(new LocalECDSASigner(getSigningPrivateKey()));

        CriJourneyRequest input =
                CriJourneyRequest.builder()
                        .ipvSessionId(SESSION_ID)
                        .ipAddress(TEST_IP_ADDRESS)
                        .language(TEST_LANGUAGE)
                        .journey(String.format(JOURNEY_BASE_URL, PASSPORT.getId()))
                        .build();

        // Act
        var responseJson = handleRequest(input, context);

        // Assert
        CriResponse response = OBJECT_MAPPER.readValue(responseJson, CriResponse.class);

        URIBuilder redirectUri = new URIBuilder(response.getCri().getRedirectUrl());
        List<NameValuePair> queryParams = redirectUri.getQueryParams();

        assertEquals(PASSPORT.getId(), response.getCri().getId());

        Optional<NameValuePair> client_id =
                queryParams.stream()
                        .filter(param -> param.getName().equals("client_id"))
                        .findFirst();
        assertTrue(client_id.isPresent());
        assertEquals(IPV_CLIENT_ID, client_id.get().getValue());

        Optional<NameValuePair> response_type =
                queryParams.stream()
                        .filter(param -> param.getName().equals("response_type"))
                        .findFirst();
        assertFalse(response_type.isPresent());

        Optional<NameValuePair> request =
                queryParams.stream().filter(param -> param.getName().equals("request")).findFirst();
        assertTrue(request.isPresent());
        JWEObject jweObject = JWEObject.parse(request.get().getValue());
        jweObject.decrypt(new RSADecrypter(getEncryptionPrivateKey()));
        assertSharedClaimsJWTIsValid(jweObject.getPayload().toString());

        assertEquals(CRI_AUTHORIZE_URL, redirectUri.removeQuery().build().toString());

        ArgumentCaptor<AuditEvent> auditEventCaptor = ArgumentCaptor.forClass(AuditEvent.class);
        verify(mockAuditService).sendAuditEvent(auditEventCaptor.capture());
        assertEquals(
                AuditEventTypes.IPV_REDIRECT_TO_CRI, auditEventCaptor.getValue().getEventName());
        verify(mockSessionCredentialService).getCredentials(SESSION_ID, TEST_USER_ID);
        verify(mockIpvSessionService, times(1)).updateIpvSession(any());
        verify(mockCriOAuthSessionService, times(1))
                .persistCriOAuthSession(any(), any(), any(), eq(MAIN_CONNECTION));
        verify(mockClientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());
    }

    @Test
    void shouldReceive200ResponseCodeAndReturnCredentialIssuerResponseWithResponseTypeParam()
            throws Exception {
        // Arrange
        when(mockOauthKeyService.getEncryptionKey(oauthCriConfig))
                .thenReturn(RSAKey.parse(RSA_ENCRYPTION_PUBLIC_JWK));
        when(configService.getActiveConnection(DCMAW)).thenReturn(MAIN_CONNECTION);
        when(configService.getOauthCriConfigForConnection(MAIN_CONNECTION, DCMAW))
                .thenReturn(oauthCriConfig);
        when(configService.getParameter(CREDENTIAL_ISSUER_SHARED_ATTRIBUTES, DCMAW.getId()))
                .thenReturn(null);
        when(configService.getLongParameter(JWT_TTL_SECONDS)).thenReturn(900L);
        when(configService.getParameter(COMPONENT_ID)).thenReturn(IPV_ISSUER);
        when(mockIpvSessionService.getIpvSession(SESSION_ID)).thenReturn(ipvSessionItem);
        mockVcHelper.when(() -> VcHelper.isSuccessfulVc(any())).thenReturn(true, true);
        when(mockSessionCredentialService.getCredentials(SESSION_ID, TEST_USER_ID))
                .thenReturn(
                        List.of(
                                generateVerifiableCredential(
                                        TEST_USER_ID,
                                        ADDRESS,
                                        vcClaimFailedWithCis(CREDENTIAL_ATTRIBUTES_1),
                                        IPV_ISSUER),
                                generateVerifiableCredential(
                                        TEST_USER_ID,
                                        ADDRESS,
                                        vcClaimFailedWithCis(CREDENTIAL_ATTRIBUTES_2),
                                        IPV_ISSUER)));
        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(mockSignerFactory.getSigner())
                .thenReturn(new LocalECDSASigner(getSigningPrivateKey()));

        CriJourneyRequest input =
                CriJourneyRequest.builder()
                        .ipvSessionId(SESSION_ID)
                        .ipAddress(TEST_IP_ADDRESS)
                        .language(TEST_LANGUAGE)
                        .journey(String.format(JOURNEY_BASE_URL, DCMAW.getId()))
                        .build();

        // Act
        var responseJson = handleRequest(input, context);

        // Assert
        CriResponse response = OBJECT_MAPPER.readValue(responseJson, CriResponse.class);

        URIBuilder redirectUri = new URIBuilder(response.getCri().getRedirectUrl());
        List<NameValuePair> queryParams = redirectUri.getQueryParams();

        assertEquals(DCMAW.getId(), response.getCri().getId());

        Optional<NameValuePair> client_id =
                queryParams.stream()
                        .filter(param -> param.getName().equals("client_id"))
                        .findFirst();
        assertTrue(client_id.isPresent());
        assertEquals(IPV_CLIENT_ID, client_id.get().getValue());

        Optional<NameValuePair> response_type =
                queryParams.stream()
                        .filter(param -> param.getName().equals("response_type"))
                        .findFirst();
        assertTrue(response_type.isPresent());
        assertEquals("code", response_type.get().getValue());

        Optional<NameValuePair> request =
                queryParams.stream().filter(param -> param.getName().equals("request")).findFirst();
        assertTrue(request.isPresent());
        JWEObject jweObject = JWEObject.parse(request.get().getValue());
        jweObject.decrypt(new RSADecrypter(getEncryptionPrivateKey()));
        assertSharedClaimsJWTIsValid(jweObject.getPayload().toString());

        assertEquals(CRI_AUTHORIZE_URL, redirectUri.removeQuery().build().toString());

        ArgumentCaptor<AuditEvent> auditEventCaptor = ArgumentCaptor.forClass(AuditEvent.class);
        verify(mockAuditService).sendAuditEvent(auditEventCaptor.capture());
        assertEquals(
                AuditEventTypes.IPV_REDIRECT_TO_CRI, auditEventCaptor.getValue().getEventName());
        verify(mockSessionCredentialService).getCredentials(SESSION_ID, TEST_USER_ID);
        verify(mockIpvSessionService, times(1)).updateIpvSession(any());
        verify(mockCriOAuthSessionService, times(1))
                .persistCriOAuthSession(any(), any(), any(), eq(MAIN_CONNECTION));
        verify(mockClientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());
    }

    @Test
    void shouldReceive200ResponseCodeAndReturnCredentialIssuerResponseWithLanguageParamForDwpKbv()
            throws Exception {
        // Arrange
        when(mockOauthKeyService.getEncryptionKey(oauthCriConfig))
                .thenReturn(RSAKey.parse(RSA_ENCRYPTION_PUBLIC_JWK));
        when(configService.getActiveConnection(DWP_KBV)).thenReturn(MAIN_CONNECTION);
        when(configService.getOauthCriConfigForConnection(MAIN_CONNECTION, DWP_KBV))
                .thenReturn(oauthCriConfig);
        when(configService.getParameter(CREDENTIAL_ISSUER_SHARED_ATTRIBUTES, DWP_KBV.getId()))
                .thenReturn(null);
        when(configService.getLongParameter(JWT_TTL_SECONDS)).thenReturn(900L);
        when(configService.getParameter(COMPONENT_ID)).thenReturn(IPV_ISSUER);
        when(mockIpvSessionService.getIpvSession(SESSION_ID)).thenReturn(ipvSessionItem);
        mockVcHelper.when(() -> VcHelper.isSuccessfulVc(any())).thenReturn(true, true);
        when(mockSessionCredentialService.getCredentials(SESSION_ID, TEST_USER_ID))
                .thenReturn(
                        List.of(
                                generateVerifiableCredential(
                                        TEST_USER_ID,
                                        ADDRESS,
                                        vcClaimFailedWithCis(CREDENTIAL_ATTRIBUTES_1),
                                        IPV_ISSUER),
                                generateVerifiableCredential(
                                        TEST_USER_ID,
                                        ADDRESS,
                                        vcClaimFailedWithCis(CREDENTIAL_ATTRIBUTES_2),
                                        IPV_ISSUER)));
        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(mockSignerFactory.getSigner())
                .thenReturn(new LocalECDSASigner(getSigningPrivateKey()));

        CriJourneyRequest input =
                CriJourneyRequest.builder()
                        .ipvSessionId(SESSION_ID)
                        .ipAddress(TEST_IP_ADDRESS)
                        .language(TEST_LANGUAGE)
                        .journey(String.format(JOURNEY_BASE_URL, DWP_KBV.getId()))
                        .build();

        // Act
        var responseJson = handleRequest(input, context);

        // Assert
        CriResponse response = OBJECT_MAPPER.readValue(responseJson, CriResponse.class);

        URIBuilder redirectUri = new URIBuilder(response.getCri().getRedirectUrl());
        List<NameValuePair> queryParams = redirectUri.getQueryParams();

        Optional<NameValuePair> lng =
                queryParams.stream().filter(param -> param.getName().equals("lng")).findFirst();
        assertTrue(lng.isPresent());
        assertEquals(TEST_LANGUAGE, lng.get().getValue());

        ArgumentCaptor<AuditEvent> auditEventCaptor = ArgumentCaptor.forClass(AuditEvent.class);
        verify(mockAuditService, times(2)).sendAuditEvent(auditEventCaptor.capture());
        var auditEvents = auditEventCaptor.getAllValues();
        assertEquals(AuditEventTypes.IPV_REDIRECT_TO_CRI, auditEvents.get(0).getEventName());
        assertEquals(AuditEventTypes.IPV_DWP_KBV_CRI_START, auditEvents.get(1).getEventName());
    }

    @Test
    void shouldReturn400IfSessionIdIsNull() throws JsonProcessingException {
        // Arrange
        CriJourneyRequest input = CriJourneyRequest.builder().journey(PASSPORT.getId()).build();

        // Act
        var responseJson = handleRequest(input, context);

        // Assert
        JourneyErrorResponse response =
                OBJECT_MAPPER.readValue(responseJson, JourneyErrorResponse.class);
        assertEquals(HttpStatusCode.BAD_REQUEST, response.getStatusCode());
        assertEquals(ErrorResponse.MISSING_IPV_SESSION_ID.getCode(), response.getCode());
        assertEquals(ErrorResponse.MISSING_IPV_SESSION_ID.getMessage(), response.getMessage());
    }

    private void assertSharedClaimsJWTIsValid(String request) throws ParseException, JOSEException {
        SignedJWT signedJWT = SignedJWT.parse(request);

        SharedClaims sharedClaims =
                OBJECT_MAPPER.convertValue(
                        signedJWT.getJWTClaimsSet().getClaim("shared_claims"), SharedClaims.class);

        assertEquals(TEST_SHARED_CLAIMS, sharedClaims);

        ECDSAVerifier verifier = new ECDSAVerifier(ECKey.parse(TEST_EC_PUBLIC_JWK));
        assertTrue(signedJWT.verify(verifier));
    }

    @Test
    void shouldSetEvidenceRequestForF2FWithMinStrengthScoreForP1() throws Exception {
        // Arrange
        when(mockOauthKeyService.getEncryptionKey(oauthCriConfig))
                .thenReturn(RSAKey.parse(RSA_ENCRYPTION_PUBLIC_JWK));
        when(configService.getActiveConnection(F2F)).thenReturn(MAIN_CONNECTION);
        when(configService.getOauthCriConfigForConnection(MAIN_CONNECTION, F2F))
                .thenReturn(oauthCriConfig);
        when(configService.getLongParameter(JWT_TTL_SECONDS)).thenReturn(900L);
        when(configService.getParameter(COMPONENT_ID)).thenReturn(IPV_ISSUER);
        when(configService.getParameter(CREDENTIAL_ISSUER_SHARED_ATTRIBUTES, F2F.getId()))
                .thenReturn("name,birthDate,address,emailAddress");
        when(mockIpvSessionService.getIpvSession(SESSION_ID)).thenReturn(ipvSessionItem);
        mockVcHelper.when(() -> VcHelper.isSuccessfulVc(any())).thenReturn(true, true);
        when(mockSessionCredentialService.getCredentials(SESSION_ID, TEST_USER_ID))
                .thenReturn(
                        List.of(
                                generateVerifiableCredential(
                                        TEST_USER_ID,
                                        ADDRESS,
                                        vcClaimFailedWithCis(CREDENTIAL_ATTRIBUTES_1),
                                        IPV_ISSUER),
                                generateVerifiableCredential(
                                        TEST_USER_ID,
                                        ADDRESS,
                                        vcClaimFailedWithCis(CREDENTIAL_ATTRIBUTES_2),
                                        IPV_ISSUER),
                                generateVerifiableCredential(
                                        TEST_USER_ID,
                                        ADDRESS,
                                        vcClaimFailedWithCis(CREDENTIAL_ATTRIBUTES_3),
                                        ADDRESS_ISSUER)));
        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        clientOAuthSessionItem.setVtr(List.of("P1"));
        when(mockGpg45ProfileEvaluator.buildScore(any()))
                .thenReturn(new Gpg45Scores(1, 1, 3, 3, 3));
        when(mockSignerFactory.getSigner())
                .thenReturn(new LocalECDSASigner(getSigningPrivateKey()));

        CriJourneyRequest input =
                CriJourneyRequest.builder()
                        .ipvSessionId(SESSION_ID)
                        .ipAddress(TEST_IP_ADDRESS)
                        .language(TEST_LANGUAGE)
                        .journey(String.format(JOURNEY_BASE_URL, F2F.getId()))
                        .build();

        // Act
        var responseJson = handleRequest(input, context);

        // Assert
        CriResponse response = OBJECT_MAPPER.readValue(responseJson, CriResponse.class);

        URIBuilder redirectUri = new URIBuilder(response.getCri().getRedirectUrl());
        List<NameValuePair> queryParams = redirectUri.getQueryParams();

        Optional<NameValuePair> request =
                queryParams.stream().filter(param -> param.getName().equals("request")).findFirst();

        assertTrue(request.isPresent());
        JWEObject jweObject = JWEObject.parse(request.get().getValue());
        jweObject.decrypt(new RSADecrypter(getEncryptionPrivateKey()));

        assertSharedClaimsJWTIsValid(jweObject.getPayload().toString());

        SignedJWT signedJWT = SignedJWT.parse(jweObject.getPayload().toString());
        JsonNode claimsSet = OBJECT_MAPPER.readTree(signedJWT.getJWTClaimsSet().toString());

        JsonNode evidenceRequested = claimsSet.get(EVIDENCE_REQUESTED);
        assertEquals(2, evidenceRequested.get("strengthScore").asInt());
        verify(mockIpvSessionService, times(1)).updateIpvSession(any());
    }

    private static Stream<Arguments> provideAppVcsForExperianFraudRequest() {
        return Stream.of(
                Arguments.of(List.of(vcDcmawPassport()), 1),
                Arguments.of(List.of(vcDcmawAsyncPassport()), 1),
                Arguments.of(List.of(vcDcmawDrivingPermitDvaM1b()), 2),
                Arguments.of(List.of(vcDcmawAsyncDrivingPermitDva()), 2),
                Arguments.of(List.of(), 2));
    }

    @ParameterizedTest
    @MethodSource("provideAppVcsForExperianFraudRequest")
    void shouldSetEvidenceRequestForFraudWithIdentityFraudScoreSetTo1IfGivenChippedDocumentVc(
            List<VerifiableCredential> appVcs, int expectedIdentityFraudScore) throws Exception {
        // Arrange
        when(mockOauthKeyService.getEncryptionKey(oauthCriConfig))
                .thenReturn(RSAKey.parse(RSA_ENCRYPTION_PUBLIC_JWK));
        when(configService.getActiveConnection(EXPERIAN_FRAUD)).thenReturn(MAIN_CONNECTION);
        when(configService.getOauthCriConfigForConnection(MAIN_CONNECTION, EXPERIAN_FRAUD))
                .thenReturn(oauthCriConfig);
        when(configService.getLongParameter(JWT_TTL_SECONDS)).thenReturn(900L);
        when(configService.getParameter(COMPONENT_ID)).thenReturn(IPV_ISSUER);
        when(configService.getParameter(
                        CREDENTIAL_ISSUER_SHARED_ATTRIBUTES, EXPERIAN_FRAUD.getId()))
                .thenReturn(null);
        when(mockIpvSessionService.getIpvSession(SESSION_ID)).thenReturn(ipvSessionItem);
        mockVcHelper.when(() -> VcHelper.isSuccessfulVc(any())).thenReturn(true, true);
        when(mockSessionCredentialService.getCredentials(SESSION_ID, TEST_USER_ID))
                .thenReturn(
                        ListUtils.union(
                                List.of(
                                        generateVerifiableCredential(
                                                TEST_USER_ID,
                                                ADDRESS,
                                                vcClaimFailedWithCis(CREDENTIAL_ATTRIBUTES_1),
                                                IPV_ISSUER)),
                                appVcs));
        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        clientOAuthSessionItem.setVtr(List.of("P1"));
        if (!appVcs.isEmpty()) {
            when(mockGpg45ProfileEvaluator.buildScore(any())).thenCallRealMethod();
        }
        when(mockSignerFactory.getSigner())
                .thenReturn(new LocalECDSASigner(getSigningPrivateKey()));

        CriJourneyRequest input =
                CriJourneyRequest.builder()
                        .ipvSessionId(SESSION_ID)
                        .ipAddress(TEST_IP_ADDRESS)
                        .language(TEST_LANGUAGE)
                        .journey(String.format(JOURNEY_BASE_URL, EXPERIAN_FRAUD.getId()))
                        .build();

        // Act
        var responseJson = handleRequest(input, context);

        // Assert
        CriResponse response = OBJECT_MAPPER.readValue(responseJson, CriResponse.class);

        URIBuilder redirectUri = new URIBuilder(response.getCri().getRedirectUrl());
        List<NameValuePair> queryParams = redirectUri.getQueryParams();

        Optional<NameValuePair> request =
                queryParams.stream().filter(param -> param.getName().equals("request")).findFirst();

        assertTrue(request.isPresent());
        JWEObject jweObject = JWEObject.parse(request.get().getValue());
        jweObject.decrypt(new RSADecrypter(getEncryptionPrivateKey()));

        SignedJWT signedJWT = SignedJWT.parse(jweObject.getPayload().toString());
        JsonNode claimsSet = OBJECT_MAPPER.readTree(signedJWT.getJWTClaimsSet().toString());

        JsonNode evidenceRequested = claimsSet.get(EVIDENCE_REQUESTED);
        assertEquals(
                expectedIdentityFraudScore, evidenceRequested.get("identityFraudScore").asInt());
        verify(mockIpvSessionService, times(1)).updateIpvSession(any());
    }

    @ParameterizedTest
    @MethodSource("journeyUriParameters")
    void shouldIncludeGivenParametersIntoCriResponseIfInJourneyUri(
            String journeyUri, Map<String, Object> expectedClaims) throws Exception {
        // Arrange
        when(mockOauthKeyService.getEncryptionKey(oauthCriConfig))
                .thenReturn(RSAKey.parse(RSA_ENCRYPTION_PUBLIC_JWK));
        when(configService.getActiveConnection(CLAIMED_IDENTITY)).thenReturn(MAIN_CONNECTION);
        when(configService.getOauthCriConfigForConnection(MAIN_CONNECTION, CLAIMED_IDENTITY))
                .thenReturn(oauthCriConfig);
        when(configService.getParameter(COMPONENT_ID)).thenReturn(IPV_ISSUER);
        when(configService.getParameter(
                        CREDENTIAL_ISSUER_SHARED_ATTRIBUTES, CLAIMED_IDENTITY.getId()))
                .thenReturn(null);
        when(configService.getLongParameter(JWT_TTL_SECONDS)).thenReturn(5000L);
        when(mockIpvSessionService.getIpvSession(SESSION_ID)).thenReturn(ipvSessionItem);
        when(mockClientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(mockSignerFactory.getSigner())
                .thenReturn(new LocalECDSASigner(getSigningPrivateKey()));

        CriJourneyRequest input =
                CriJourneyRequest.builder()
                        .ipvSessionId(SESSION_ID)
                        .ipAddress(TEST_IP_ADDRESS)
                        .language(TEST_LANGUAGE)
                        .journey(String.format(JOURNEY_BASE_URL, journeyUri))
                        .build();

        // Act
        var responseJson = handleRequest(input, context);

        // Assert
        CriResponse response = OBJECT_MAPPER.readValue(responseJson, CriResponse.class);

        URIBuilder redirectUri = new URIBuilder(response.getCri().getRedirectUrl());
        List<NameValuePair> queryParams = redirectUri.getQueryParams();

        Optional<NameValuePair> request =
                queryParams.stream().filter(param -> param.getName().equals("request")).findFirst();

        assertTrue(request.isPresent(), "Expected request parameter to be present");
        JWEObject jweObject = JWEObject.parse(request.get().getValue());
        jweObject.decrypt(new RSADecrypter(getEncryptionPrivateKey()));

        SignedJWT signedJWT = SignedJWT.parse(jweObject.getPayload().toString());
        JWTClaimsSet claimsSet = signedJWT.getJWTClaimsSet();

        for (var entry : expectedClaims.entrySet()) {
            String expectedClaim = OBJECT_MAPPER.writeValueAsString(entry.getValue());
            String actualClaim =
                    OBJECT_MAPPER.writeValueAsString(claimsSet.getClaim(entry.getKey()));
            assertEquals(
                    expectedClaim,
                    actualClaim,
                    () ->
                            String.format(
                                    "Expected claim for key=%s to be %s, but found %s",
                                    entry.getKey(), expectedClaim, actualClaim));
        }
    }

    @Test
    void shouldLogRuntimeExceptionsAndRethrow() throws Exception {
        // Arrange
        when(mockIpvSessionService.getIpvSession(SESSION_ID))
                .thenThrow(new RuntimeException("Test error"));
        CriJourneyRequest input =
                CriJourneyRequest.builder()
                        .ipvSessionId(SESSION_ID)
                        .ipAddress(TEST_IP_ADDRESS)
                        .language(TEST_LANGUAGE)
                        .journey(String.format(JOURNEY_BASE_URL, DWP_KBV.getId()))
                        .build();

        var logCollector = LogCollector.getLogCollectorFor(BuildCriOauthRequestHandler.class);

        // Act
        var thrown =
                assertThrows(
                        Exception.class,
                        () -> handleRequest(input, context),
                        "Expected handleRequest() to throw, but it didn't");

        // Assert
        assertEquals("Test error", thrown.getMessage());
        var logMessage = logCollector.getLogMessages().get(0);
        assertThat(logMessage, containsString("Unhandled lambda exception"));
        assertThat(logMessage, containsString("Test error"));
    }

    private static Stream<Arguments> journeyUriParameters() {
        return Stream.of(
                Arguments.of(CRI_WITH_CONTEXT, Map.of(CONTEXT, TEST_CONTEXT)),
                Arguments.of(
                        CRI_WITH_EVIDENCE_REQUEST,
                        Map.of(EVIDENCE_REQUESTED, TEST_EVIDENCE_REQUESTED)),
                Arguments.of(
                        CRI_WITH_CONTEXT_AND_EVIDENCE_REQUEST,
                        Map.of(
                                CONTEXT,
                                TEST_CONTEXT,
                                EVIDENCE_REQUESTED,
                                TEST_EVIDENCE_REQUESTED)));
    }

    private void assertErrorResponse(
            int httpStatusCode, String responseJson, ErrorResponse errorResponse)
            throws JsonProcessingException {
        JourneyErrorResponse response =
                OBJECT_MAPPER.readValue(responseJson, JourneyErrorResponse.class);
        assertEquals(httpStatusCode, response.getStatusCode());
        assertEquals(errorResponse.getCode(), response.getCode());
        assertEquals(errorResponse.getMessage(), response.getMessage());
    }

    private ECKey getSigningPrivateKey() throws Exception {
        return ECKey.parse(EC_PRIVATE_KEY_JWK);
    }

    private PrivateKey getEncryptionPrivateKey()
            throws NoSuchAlgorithmException, InvalidKeySpecException {
        return KeyFactory.getInstance("RSA")
                .generatePrivate(
                        new PKCS8EncodedKeySpec(
                                Base64.getDecoder().decode(RSA_ENCRYPTION_PRIVATE_KEY)));
    }

    private static String getJsonResponse(Map<String, Object> response)
            throws JsonProcessingException {
        return OBJECT_MAPPER.writeValueAsString(response);
    }

    private String handleRequest(CriJourneyRequest event, Context context)
            throws JsonProcessingException {
        final var response = buildCriOauthRequestHandler.handleRequest(event, context);
        return getJsonResponse(OBJECT_MAPPER.convertValue(response, new TypeReference<>() {}));
    }
}
