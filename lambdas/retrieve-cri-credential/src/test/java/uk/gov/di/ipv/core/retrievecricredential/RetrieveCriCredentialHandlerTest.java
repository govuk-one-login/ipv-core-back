package uk.gov.di.ipv.core.retrievecricredential;

import com.amazonaws.services.lambda.runtime.Context;
import com.fasterxml.jackson.databind.JsonNode;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.OAuth2Error;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.auditing.AuditEvent;
import uk.gov.di.ipv.core.library.auditing.AuditEventTypes;
import uk.gov.di.ipv.core.library.auditing.AuditEventUser;
import uk.gov.di.ipv.core.library.auditing.AuditExtensionsVcEvidence;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.IpvJourneyTypes;
import uk.gov.di.ipv.core.library.dto.CredentialIssuerConfig;
import uk.gov.di.ipv.core.library.dto.VisitedCredentialIssuerDetailsDto;
import uk.gov.di.ipv.core.library.exceptions.CiPostMitigationsException;
import uk.gov.di.ipv.core.library.exceptions.CiPutException;
import uk.gov.di.ipv.core.library.exceptions.SqsException;
import uk.gov.di.ipv.core.library.exceptions.VerifiableCredentialException;
import uk.gov.di.ipv.core.library.helpers.SecureTokenHelper;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.CriOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.CiStorageService;
import uk.gov.di.ipv.core.library.service.ClientOAuthSessionDetailsService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.CriOAuthSessionService;
import uk.gov.di.ipv.core.library.service.CriResponseService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.validation.VerifiableCredentialJwtValidator;
import uk.gov.di.ipv.core.library.verifiablecredential.domain.VerifiableCredentialResponse;
import uk.gov.di.ipv.core.library.verifiablecredential.domain.VerifiableCredentialStatus;
import uk.gov.di.ipv.core.library.verifiablecredential.service.VerifiableCredentialService;

import java.net.URI;
import java.net.URISyntaxException;
import java.text.ParseException;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.COMPONENT_ID;
import static uk.gov.di.ipv.core.library.domain.CriConstants.ADDRESS_CRI;
import static uk.gov.di.ipv.core.library.domain.CriConstants.CLAIMED_IDENTITY_CRI;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.RSA_ENCRYPTION_PUBLIC_JWK;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.SIGNED_ADDRESS_VC;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.SIGNED_CONTRA_INDICATORS;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.SIGNED_VC_1;

@ExtendWith(MockitoExtension.class)
class RetrieveCriCredentialHandlerTest {
    private static final String ACCESS_TOKEN = "Bearer dGVzdAo=";
    private static final String CREDENTIAL_ISSUER_ID = "PassportIssuer";
    private static final String TEST_USER_ID = "test-user-id";
    private static final String TEST_CLIENT_OAUTH_STATE = "test-client-oauth-state";
    private static final String TEST_CRI_OAUTH_STATE = "test-cri-oauth-state";
    private static final String TEST_IP_ADDRESS = "192.168.1.100";
    private static final String CODE = "code";
    private static final String MESSAGE = "message";
    private static final String STATUS_CODE = "statusCode";

    private static final String TEST_IPV_SESSION_ID = UUID.randomUUID().toString();
    private static final String passportIssuerId = CREDENTIAL_ISSUER_ID;
    public static final String TEST_ISSUER = "test-issuer";

    private static final String USE_POST_MITIGATIONS_FEATURE_FLAG = "usePostMitigations";
    private static final SignedJWT TEST_SIGNED_ADDRESS_VC;

    @Mock private Context context;
    @Mock private VerifiableCredentialService verifiableCredentialService;
    @Mock private AuditService auditService;
    @Mock private static ConfigService configService;
    @Mock private VerifiableCredentialJwtValidator verifiableCredentialJwtValidator;
    @Mock private IpvSessionService ipvSessionService;
    @Mock private IpvSessionItem ipvSessionItem;
    @Mock private CiStorageService ciStorageService;
    @Mock private CriOAuthSessionService criOAuthSessionService;
    @Mock private ClientOAuthSessionDetailsService mockClientOAuthSessionService;

    @Mock private CriResponseService criResponseService;
    private static CriOAuthSessionItem criOAuthSessionItem;
    @InjectMocks private RetrieveCriCredentialHandler handler;

    private static BearerAccessToken testBearerAccessToken;
    private static CredentialIssuerConfig testPassportIssuer;
    private static Map<String, String> testInput;
    private static final String testSessionId = SecureTokenHelper.generate();
    private static final String testApiKey = "test-api-key";
    private static final String testComponentId = "https://ipv-core-test.example.com";
    private static CredentialIssuerConfig addressConfig = null;
    private static CredentialIssuerConfig claimedIdentityConfig = null;

    static {
        try {
            addressConfig =
                    new CredentialIssuerConfig(
                            new URI("http://example.com/token"),
                            new URI("http://example.com/credential"),
                            new URI("http://example.com/authorize"),
                            "ipv-core",
                            "test-jwk",
                            "test-encryption-jwk",
                            "test-audience",
                            new URI("http://example.com/redirect"),
                            true);
            claimedIdentityConfig =
                    new CredentialIssuerConfig(
                            new URI("http://example.com/token"),
                            new URI("http://example.com/credential"),
                            new URI("http://example.com/authorize"),
                            "ipv-core",
                            "test-jwk",
                            "test-encryption-jwk",
                            "test-claimed-identity",
                            new URI("http://example.com/redirect"),
                            true);
        } catch (URISyntaxException e) {
            e.printStackTrace();
        }
        try {
            TEST_SIGNED_ADDRESS_VC = SignedJWT.parse(SIGNED_ADDRESS_VC);
        } catch (ParseException e) {
            throw new RuntimeException(e);
        }
    }

    @BeforeAll
    static void setUp() throws URISyntaxException, com.nimbusds.oauth2.sdk.ParseException {
        testPassportIssuer =
                new CredentialIssuerConfig(
                        new URI("https://www.example.com"),
                        new URI("https://www.example.com/credential"),
                        new URI("https://www.example.com/authorize"),
                        "ipv-core",
                        "{}",
                        RSA_ENCRYPTION_PUBLIC_JWK,
                        "test-audience",
                        new URI("https://www.example.com/credential-issuers/callback/criId"),
                        true);

        testBearerAccessToken = BearerAccessToken.parse(ACCESS_TOKEN);

        testInput = Map.of("ipvSessionId", testSessionId, "ipAddress", TEST_IP_ADDRESS);

        criOAuthSessionItem =
                CriOAuthSessionItem.builder()
                        .criOAuthSessionId(TEST_CRI_OAUTH_STATE)
                        .criId(CREDENTIAL_ISSUER_ID)
                        .accessToken(ACCESS_TOKEN)
                        .build();
    }

    @Test
    void shouldReturnJourneyResponseOnSuccessfulRequest() throws Exception {
        when(ipvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);
        when(configService.getCredentialIssuerActiveConnectionConfig(CLAIMED_IDENTITY_CRI))
                .thenReturn(claimedIdentityConfig);
        when(configService.getCredentialIssuerActiveConnectionConfig(ADDRESS_CRI))
                .thenReturn(addressConfig);
        when(verifiableCredentialService.getVerifiableCredentialResponse(
                        testBearerAccessToken,
                        testPassportIssuer,
                        testApiKey,
                        CREDENTIAL_ISSUER_ID))
                .thenReturn(
                        VerifiableCredentialResponse.builder()
                                .verifiableCredentials(List.of(SignedJWT.parse(SIGNED_VC_1)))
                                .build());

        mockServiceCallsAndSessionItem();
        when(ipvSessionItem.getJourneyType()).thenReturn(IpvJourneyTypes.IPV_CORE_MAIN_JOURNEY);

        Map<String, Object> output = handler.handleRequest(testInput, context);

        ArgumentCaptor<AuditEvent> auditEventCaptor = ArgumentCaptor.forClass(AuditEvent.class);
        verify(auditService, times(1)).sendAuditEvent(auditEventCaptor.capture());
        List<AuditEvent> auditEvents = auditEventCaptor.getAllValues();
        assertEquals(AuditEventTypes.IPV_VC_RECEIVED, auditEvents.get(0).getEventName());

        verify(verifiableCredentialJwtValidator)
                .validate(any(SignedJWT.class), eq(testPassportIssuer), eq(TEST_USER_ID));

        assertEquals("/journey/next", output.get("journey"));
        assertEquals("ipv-core-main-journey", output.get("journeyType"));
        verify(criOAuthSessionService, times(1)).getCriOauthSessionItem(any());
    }

    @Test
    void shouldUpdateSessionWithDetailsOfVisitedCri() throws ParseException {
        when(configService.getCredentialIssuerActiveConnectionConfig(CREDENTIAL_ISSUER_ID))
                .thenReturn(testPassportIssuer);
        when(configService.getCredentialIssuerActiveConnectionConfig(CLAIMED_IDENTITY_CRI))
                .thenReturn(claimedIdentityConfig);
        when(configService.getCredentialIssuerActiveConnectionConfig(ADDRESS_CRI))
                .thenReturn(addressConfig);
        when(configService.getSsmParameter(COMPONENT_ID)).thenReturn(testComponentId);
        when(configService.getCriPrivateApiKey(anyString())).thenReturn(testApiKey);
        when(verifiableCredentialService.getVerifiableCredentialResponse(
                        testBearerAccessToken,
                        testPassportIssuer,
                        testApiKey,
                        CREDENTIAL_ISSUER_ID))
                .thenReturn(
                        VerifiableCredentialResponse.builder()
                                .verifiableCredentials(List.of(SignedJWT.parse(SIGNED_VC_1)))
                                .build());

        IpvSessionItem ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setIpvSessionId("someIpvSessionId");
        ipvSessionItem.setJourneyType(IpvJourneyTypes.IPV_CORE_MAIN_JOURNEY);
        when(ipvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);
        when(criOAuthSessionService.getCriOauthSessionItem(any())).thenReturn(criOAuthSessionItem);
        when(mockClientOAuthSessionService.getClientOAuthSession(any()))
                .thenReturn(getClientOAuthSessionItem());

        handler.handleRequest(testInput, context);

        ArgumentCaptor<IpvSessionItem> ipvSessionItemArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(ipvSessionService).updateIpvSession(ipvSessionItemArgumentCaptor.capture());
        var visitedCredentialIssuerDetails =
                ipvSessionItemArgumentCaptor.getValue().getVisitedCredentialIssuerDetails();
        assertEquals(1, visitedCredentialIssuerDetails.size());
        assertEquals(passportIssuerId, visitedCredentialIssuerDetails.get(0).getCriId());
        assertEquals(TEST_ISSUER, visitedCredentialIssuerDetails.get(0).getCriIssuer());
        assertTrue(visitedCredentialIssuerDetails.get(0).isReturnedWithVc());
        assertNull(visitedCredentialIssuerDetails.get(0).getOauthError());
        verify(criOAuthSessionService, times(1)).getCriOauthSessionItem(any());
    }

    @Test
    void shouldReturn400IfMissingIpvSessionIdHeader() {
        Map<String, Object> output = handler.handleRequest(Collections.emptyMap(), context);

        assertEquals(HTTPResponse.SC_BAD_REQUEST, output.get(STATUS_CODE));
        assertEquals(
                String.valueOf(ErrorResponse.MISSING_IPV_SESSION_ID.getCode()),
                String.valueOf(output.get(CODE)));
        assertEquals(
                String.valueOf(ErrorResponse.MISSING_IPV_SESSION_ID.getMessage()),
                String.valueOf(output.get(MESSAGE)));
    }

    @Test
    void shouldReturnErrorJourneyResponseIfCredentialIssuerServiceGetCredentialThrows() {
        mockServiceCalls();

        when(verifiableCredentialService.getVerifiableCredentialResponse(
                        any(), any(), anyString(), anyString()))
                .thenThrow(
                        new VerifiableCredentialException(
                                HTTPResponse.SC_SERVER_ERROR,
                                ErrorResponse.FAILED_TO_GET_CREDENTIAL_FROM_ISSUER));

        Map<String, Object> output = handler.handleRequest(testInput, context);

        assertEquals("/journey/error", output.get("journey"));
    }

    @Test
    void shouldReturnErrorJourneyResponseIfSqsExceptionIsThrown() throws Exception {
        mockServiceCallsAndSessionItem();
        when(configService.getCredentialIssuerActiveConnectionConfig(CLAIMED_IDENTITY_CRI))
                .thenReturn(claimedIdentityConfig);
        when(configService.getCredentialIssuerActiveConnectionConfig(ADDRESS_CRI))
                .thenReturn(addressConfig);
        when(verifiableCredentialService.getVerifiableCredentialResponse(
                        testBearerAccessToken,
                        testPassportIssuer,
                        testApiKey,
                        CREDENTIAL_ISSUER_ID))
                .thenReturn(
                        VerifiableCredentialResponse.builder()
                                .verifiableCredentials(List.of(SignedJWT.parse(SIGNED_VC_1)))
                                .build());

        doThrow(new SqsException("Test sqs error"))
                .when(auditService)
                .sendAuditEvent(any(AuditEvent.class));

        Map<String, Object> output = handler.handleRequest(testInput, context);

        assertEquals("/journey/error", output.get("journey"));
    }

    @Test
    void shouldReturnErrorJourneyIfVCFailsValidation() throws Exception {
        when(configService.getCredentialIssuerActiveConnectionConfig(CLAIMED_IDENTITY_CRI))
                .thenReturn(claimedIdentityConfig);
        when(configService.getCredentialIssuerActiveConnectionConfig(ADDRESS_CRI))
                .thenReturn(addressConfig);
        when(verifiableCredentialService.getVerifiableCredentialResponse(
                        testBearerAccessToken,
                        testPassportIssuer,
                        testApiKey,
                        CREDENTIAL_ISSUER_ID))
                .thenReturn(
                        VerifiableCredentialResponse.builder()
                                .verifiableCredentials(List.of(SignedJWT.parse(SIGNED_VC_1)))
                                .build());

        mockServiceCallsAndSessionItem();

        doThrow(
                        new VerifiableCredentialException(
                                HTTPResponse.SC_SERVER_ERROR,
                                ErrorResponse.FAILED_TO_VALIDATE_VERIFIABLE_CREDENTIAL))
                .when(verifiableCredentialJwtValidator)
                .validate(any(), any(), any());

        Map<String, Object> output = handler.handleRequest(testInput, context);

        assertEquals("/journey/error", output.get("journey"));
    }

    @Test
    void shouldSendIpvVcReceivedAuditEvent() throws Exception {
        when(ipvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);
        when(configService.getCredentialIssuerActiveConnectionConfig(CLAIMED_IDENTITY_CRI))
                .thenReturn(claimedIdentityConfig);
        when(configService.getCredentialIssuerActiveConnectionConfig(ADDRESS_CRI))
                .thenReturn(addressConfig);
        when(verifiableCredentialService.getVerifiableCredentialResponse(
                        testBearerAccessToken,
                        testPassportIssuer,
                        testApiKey,
                        CREDENTIAL_ISSUER_ID))
                .thenReturn(
                        VerifiableCredentialResponse.builder()
                                .verifiableCredentials(
                                        List.of(SignedJWT.parse(SIGNED_CONTRA_INDICATORS)))
                                .build());
        mockServiceCallsAndSessionItem();
        when(ipvSessionItem.getJourneyType()).thenReturn(IpvJourneyTypes.IPV_CORE_MAIN_JOURNEY);

        handler.handleRequest(testInput, context);

        ArgumentCaptor<AuditEvent> auditEventCaptor = ArgumentCaptor.forClass(AuditEvent.class);
        verify(auditService, times(1)).sendAuditEvent(auditEventCaptor.capture());
        List<AuditEvent> auditEvents = auditEventCaptor.getAllValues();
        assertEquals(AuditEventTypes.IPV_VC_RECEIVED, auditEvents.get(0).getEventName());

        assertEquals(testComponentId, auditEvents.get(0).getComponentId());
        AuditEventUser auditEventUser = auditEvents.get(0).getUser();
        assertEquals(TEST_USER_ID, auditEventUser.getUserId());
        assertEquals(testSessionId, auditEventUser.getSessionId());

        AuditExtensionsVcEvidence auditExtensionsVcEvidence =
                (AuditExtensionsVcEvidence) auditEvents.get(0).getExtensions();
        assertEquals("https://issuer.example.com", auditExtensionsVcEvidence.getIss());
        JsonNode evidenceItem = auditExtensionsVcEvidence.getEvidence().get(0);
        assertEquals("IdentityCheck", evidenceItem.get("type").asText());
        assertEquals("DSJJSEE29392", evidenceItem.get("txn").asText());
        assertEquals("0", evidenceItem.get("verificationScore").asText());
        assertEquals("[ \"A02\", \"A03\" ]", evidenceItem.get("ci").toPrettyString());
        verify(criOAuthSessionService, times(1)).getCriOauthSessionItem(any());
        verify(ciStorageService, never()).submitMitigatingVcList(any(), any(), any());
    }

    @Test
    void shouldSendIpvVcReceivedAuditEventWhenVcEvidenceIsMissing() throws Exception {
        when(verifiableCredentialService.getVerifiableCredentialResponse(
                        testBearerAccessToken,
                        testPassportIssuer,
                        testApiKey,
                        CREDENTIAL_ISSUER_ID))
                .thenReturn(
                        VerifiableCredentialResponse.builder()
                                .verifiableCredentials(List.of(SignedJWT.parse(SIGNED_ADDRESS_VC)))
                                .build());
        when(configService.getCredentialIssuerActiveConnectionConfig(ADDRESS_CRI))
                .thenReturn(addressConfig);
        when(configService.getCredentialIssuerActiveConnectionConfig(CLAIMED_IDENTITY_CRI))
                .thenReturn(claimedIdentityConfig);
        mockServiceCallsAndSessionItem();
        when(ipvSessionItem.getJourneyType()).thenReturn(IpvJourneyTypes.IPV_CORE_MAIN_JOURNEY);

        handler.handleRequest(testInput, context);

        ArgumentCaptor<AuditEvent> argumentCaptor = ArgumentCaptor.forClass(AuditEvent.class);
        verify(auditService, times(1)).sendAuditEvent(argumentCaptor.capture());
        AuditEvent event = argumentCaptor.getAllValues().get(0);
        assertEquals(AuditEventTypes.IPV_VC_RECEIVED, event.getEventName());

        assertEquals(testComponentId, event.getComponentId());

        AuditEventUser auditEventUser = event.getUser();
        assertEquals(TEST_USER_ID, auditEventUser.getUserId());
        assertEquals(testSessionId, auditEventUser.getSessionId());

        AuditExtensionsVcEvidence auditExtensionsVcEvidence =
                (AuditExtensionsVcEvidence) argumentCaptor.getValue().getExtensions();
        assertEquals(
                "https://staging-di-ipv-cri-address-front.london.cloudapps.digital",
                auditExtensionsVcEvidence.getIss());
        assertNull(auditExtensionsVcEvidence.getEvidence());
        verify(criOAuthSessionService, times(1)).getCriOauthSessionItem(any());
    }

    @Test
    void shouldNotStoreVcIfFailedToSubmitItToTheCiStorageSystem() throws Exception {
        when(verifiableCredentialService.getVerifiableCredentialResponse(
                        testBearerAccessToken,
                        testPassportIssuer,
                        testApiKey,
                        CREDENTIAL_ISSUER_ID))
                .thenReturn(
                        VerifiableCredentialResponse.builder()
                                .verifiableCredentials(List.of(SignedJWT.parse(SIGNED_ADDRESS_VC)))
                                .build());
        when(configService.getCredentialIssuerActiveConnectionConfig(CREDENTIAL_ISSUER_ID))
                .thenReturn(testPassportIssuer);
        when(configService.getCredentialIssuerActiveConnectionConfig(ADDRESS_CRI))
                .thenReturn(addressConfig);
        when(configService.getCredentialIssuerActiveConnectionConfig(CLAIMED_IDENTITY_CRI))
                .thenReturn(claimedIdentityConfig);
        when(configService.getSsmParameter(COMPONENT_ID)).thenReturn(testComponentId);
        when(configService.getCriPrivateApiKey(anyString())).thenReturn(testApiKey);
        when(mockClientOAuthSessionService.getClientOAuthSession(any()))
                .thenReturn(getClientOAuthSessionItem());
        when(configService.getFeatureFlag(USE_POST_MITIGATIONS_FEATURE_FLAG)).thenReturn("true");

        IpvSessionItem ipvSessionItem = new IpvSessionItem();
        when(criOAuthSessionService.getCriOauthSessionItem(any())).thenReturn(criOAuthSessionItem);
        when(ipvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);

        doThrow(new CiPutException("Lambda execution failed"))
                .when(ciStorageService)
                .submitVC(any(SignedJWT.class), anyString(), anyString());

        handler.handleRequest(testInput, context);

        verify(verifiableCredentialService, never()).persistUserCredentials(any(), any(), any());
        verify(ciStorageService, never()).submitMitigatingVcList(any(), any(), any());

        ArgumentCaptor<IpvSessionItem> ipvSessionItemArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(ipvSessionService).updateIpvSession(ipvSessionItemArgumentCaptor.capture());
        var updatedIpvSessionItem = ipvSessionItemArgumentCaptor.getValue();
        assertEquals(1, updatedIpvSessionItem.getVisitedCredentialIssuerDetails().size());
        assertEquals(
                CREDENTIAL_ISSUER_ID,
                updatedIpvSessionItem.getVisitedCredentialIssuerDetails().get(0).getCriId());
        assertFalse(
                updatedIpvSessionItem
                        .getVisitedCredentialIssuerDetails()
                        .get(0)
                        .isReturnedWithVc());
        assertEquals(
                OAuth2Error.SERVER_ERROR_CODE,
                updatedIpvSessionItem.getVisitedCredentialIssuerDetails().get(0).getOauthError());
        verify(criOAuthSessionService, times(1)).getCriOauthSessionItem(any());
    }

    @Test
    void shouldSendVCToCIMITPostMitigationsWhenFeatureEnabled() throws Exception {
        when(verifiableCredentialService.getVerifiableCredentialResponse(
                        testBearerAccessToken,
                        testPassportIssuer,
                        testApiKey,
                        CREDENTIAL_ISSUER_ID))
                .thenReturn(
                        VerifiableCredentialResponse.builder()
                                .verifiableCredentials(List.of(TEST_SIGNED_ADDRESS_VC))
                                .build());
        when(configService.getCredentialIssuerActiveConnectionConfig(CREDENTIAL_ISSUER_ID))
                .thenReturn(testPassportIssuer);
        when(configService.getCredentialIssuerActiveConnectionConfig(ADDRESS_CRI))
                .thenReturn(addressConfig);
        when(configService.getCredentialIssuerActiveConnectionConfig(CLAIMED_IDENTITY_CRI))
                .thenReturn(claimedIdentityConfig);
        when(configService.getSsmParameter(COMPONENT_ID)).thenReturn(testComponentId);
        when(configService.getCriPrivateApiKey(anyString())).thenReturn(testApiKey);
        when(mockClientOAuthSessionService.getClientOAuthSession(any()))
                .thenReturn(getClientOAuthSessionItem());
        when(configService.getFeatureFlag(USE_POST_MITIGATIONS_FEATURE_FLAG)).thenReturn("true");

        IpvSessionItem ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setJourneyType(IpvJourneyTypes.IPV_CORE_MAIN_JOURNEY);
        when(criOAuthSessionService.getCriOauthSessionItem(any())).thenReturn(criOAuthSessionItem);
        when(ipvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);

        handler.handleRequest(testInput, context);

        ArgumentCaptor<SignedJWT> persistedVcCaptor = ArgumentCaptor.forClass(SignedJWT.class);
        verify(verifiableCredentialService)
                .persistUserCredentials(persistedVcCaptor.capture(), any(), any());
        var persistedVc = persistedVcCaptor.getValue();
        assertEquals(TEST_SIGNED_ADDRESS_VC, persistedVc);

        ArgumentCaptor<SignedJWT> submittedVcCaptor = ArgumentCaptor.forClass(SignedJWT.class);
        verify(ciStorageService).submitVC(submittedVcCaptor.capture(), anyString(), anyString());
        var submittedVc = submittedVcCaptor.getValue();
        assertEquals(TEST_SIGNED_ADDRESS_VC, submittedVc);

        @SuppressWarnings("unchecked")
        ArgumentCaptor<List<String>> postedVcsCaptor = ArgumentCaptor.forClass(List.class);
        verify(ciStorageService)
                .submitMitigatingVcList(postedVcsCaptor.capture(), anyString(), anyString());
        var postedVcs = postedVcsCaptor.getValue();
        assertEquals(1, postedVcs.size());
        assertEquals(TEST_SIGNED_ADDRESS_VC.serialize(), postedVcs.get(0));

        ArgumentCaptor<IpvSessionItem> ipvSessionItemArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(ipvSessionService).updateIpvSession(ipvSessionItemArgumentCaptor.capture());
        var visitedCredentialIssuerDetails =
                ipvSessionItemArgumentCaptor.getValue().getVisitedCredentialIssuerDetails();
        assertEquals(1, visitedCredentialIssuerDetails.size());
        assertEquals(CREDENTIAL_ISSUER_ID, visitedCredentialIssuerDetails.get(0).getCriId());
        assertTrue(visitedCredentialIssuerDetails.get(0).isReturnedWithVc());
        assertNull(visitedCredentialIssuerDetails.get(0).getOauthError());

        verify(criOAuthSessionService, times(1)).getCriOauthSessionItem(any());
    }

    @Test
    void shouldNotStoreVcIfFailedToPostMitigationsToCIMIT() throws Exception {
        when(verifiableCredentialService.getVerifiableCredentialResponse(
                        testBearerAccessToken,
                        testPassportIssuer,
                        testApiKey,
                        CREDENTIAL_ISSUER_ID))
                .thenReturn(
                        VerifiableCredentialResponse.builder()
                                .verifiableCredentials(List.of(TEST_SIGNED_ADDRESS_VC))
                                .build());
        when(configService.getCredentialIssuerActiveConnectionConfig(CREDENTIAL_ISSUER_ID))
                .thenReturn(testPassportIssuer);
        when(configService.getCredentialIssuerActiveConnectionConfig(ADDRESS_CRI))
                .thenReturn(addressConfig);
        when(configService.getCredentialIssuerActiveConnectionConfig(CLAIMED_IDENTITY_CRI))
                .thenReturn(claimedIdentityConfig);
        when(configService.getSsmParameter(COMPONENT_ID)).thenReturn(testComponentId);
        when(configService.getCriPrivateApiKey(anyString())).thenReturn(testApiKey);
        when(mockClientOAuthSessionService.getClientOAuthSession(any()))
                .thenReturn(getClientOAuthSessionItem());
        when(configService.getFeatureFlag(USE_POST_MITIGATIONS_FEATURE_FLAG)).thenReturn("true");

        IpvSessionItem ipvSessionItem = new IpvSessionItem();
        when(criOAuthSessionService.getCriOauthSessionItem(any())).thenReturn(criOAuthSessionItem);
        when(ipvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);

        doThrow(new CiPostMitigationsException("Lambda execution failed"))
                .when(ciStorageService)
                .submitMitigatingVcList(anyList(), anyString(), anyString());

        handler.handleRequest(testInput, context);

        verify(verifiableCredentialService, never()).persistUserCredentials(any(), any(), any());
        ArgumentCaptor<SignedJWT> submittedVcCaptor = ArgumentCaptor.forClass(SignedJWT.class);
        verify(ciStorageService).submitVC(submittedVcCaptor.capture(), anyString(), anyString());
        var submittedVc = submittedVcCaptor.getValue();
        assertEquals(TEST_SIGNED_ADDRESS_VC, submittedVc);

        ArgumentCaptor<IpvSessionItem> ipvSessionItemArgumentCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(ipvSessionService).updateIpvSession(ipvSessionItemArgumentCaptor.capture());
        var updatedIpvSessionItem = ipvSessionItemArgumentCaptor.getValue();
        assertEquals(1, updatedIpvSessionItem.getVisitedCredentialIssuerDetails().size());
        assertEquals(
                CREDENTIAL_ISSUER_ID,
                updatedIpvSessionItem.getVisitedCredentialIssuerDetails().get(0).getCriId());
        assertFalse(
                updatedIpvSessionItem
                        .getVisitedCredentialIssuerDetails()
                        .get(0)
                        .isReturnedWithVc());
        assertEquals(
                OAuth2Error.SERVER_ERROR_CODE,
                updatedIpvSessionItem.getVisitedCredentialIssuerDetails().get(0).getOauthError());
        verify(criOAuthSessionService, times(1)).getCriOauthSessionItem(any());
    }

    @Test
    void shouldPassNullApiKeyWhenCriDoesNotRequireApiKey() throws Exception {
        CredentialIssuerConfig testCriNotRequiringApiKey =
                new CredentialIssuerConfig(
                        new URI("https://www.example.com"),
                        new URI("https://www.example.com/credential"),
                        new URI("https://www.example.com/authorize"),
                        "ipv-core",
                        "{}",
                        RSA_ENCRYPTION_PUBLIC_JWK,
                        "test-audience",
                        new URI("https://www.example.com/credential-issuers/callback/criId"),
                        false);
        when(configService.getCredentialIssuerActiveConnectionConfig(CREDENTIAL_ISSUER_ID))
                .thenReturn(testCriNotRequiringApiKey);
        when(configService.getCredentialIssuerActiveConnectionConfig(CLAIMED_IDENTITY_CRI))
                .thenReturn(claimedIdentityConfig);
        when(configService.getCredentialIssuerActiveConnectionConfig(ADDRESS_CRI))
                .thenReturn(addressConfig);
        when(configService.getSsmParameter(COMPONENT_ID)).thenReturn(testComponentId);
        when(ipvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);
        when(criOAuthSessionService.getCriOauthSessionItem(any())).thenReturn(criOAuthSessionItem);
        when(ipvSessionItem.getIpvSessionId()).thenReturn(testSessionId);
        when(ipvSessionItem.getJourneyType()).thenReturn(IpvJourneyTypes.IPV_CORE_MAIN_JOURNEY);
        when(mockClientOAuthSessionService.getClientOAuthSession(any()))
                .thenReturn(getClientOAuthSessionItem());
        when(ipvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);
        when(verifiableCredentialService.getVerifiableCredentialResponse(
                        any(), any(), any(), any()))
                .thenReturn(
                        VerifiableCredentialResponse.builder()
                                .verifiableCredentials(List.of(SignedJWT.parse(SIGNED_VC_1)))
                                .build());

        Map<String, Object> output = handler.handleRequest(testInput, context);

        verify(verifiableCredentialService)
                .getVerifiableCredentialResponse(
                        testBearerAccessToken,
                        testCriNotRequiringApiKey,
                        null,
                        CREDENTIAL_ISSUER_ID);
        assertEquals("/journey/next", output.get("journey"));
    }

    @Test
    void shouldReturnJourneyPendingResponseOnSuccessfulPendingCriResponse() {
        final String expectedIssuerResponse =
                "{\"sub\":\""
                        + TEST_USER_ID
                        + "\","
                        + "\"https://vocab.account.gov.uk/v1/credentialStatus\":\"pending\"}";
        when(verifiableCredentialService.getVerifiableCredentialResponse(
                        testBearerAccessToken,
                        testPassportIssuer,
                        testApiKey,
                        CREDENTIAL_ISSUER_ID))
                .thenReturn(
                        VerifiableCredentialResponse.builder()
                                .userId(TEST_USER_ID)
                                .credentialStatus(VerifiableCredentialStatus.PENDING)
                                .build());

        IpvSessionItem testIpvSessionItem = makeTestIpvSessionItem(TEST_IPV_SESSION_ID);
        testIpvSessionItem.setJourneyType(IpvJourneyTypes.IPV_CORE_MAIN_JOURNEY);
        mockServiceCalls(testIpvSessionItem);

        Map<String, Object> output = handler.handleRequest(testInput, context);

        assertEquals("/journey/pending", output.get("journey"));
        assertEquals("ipv-core-main-journey", output.get("journeyType"));
        verify(criOAuthSessionService, times(1)).getCriOauthSessionItem(any());

        verifyPersistedCriResponse(
                TEST_USER_ID, CREDENTIAL_ISSUER_ID, expectedIssuerResponse, TEST_CRI_OAUTH_STATE);

        verifyPersistedVisitedCredentialIssuerDetails(CREDENTIAL_ISSUER_ID, false, null);
    }

    @Test
    void shouldReturnErrorJourneyOnPendingCriResponseWithMismatchedUser() {
        when(verifiableCredentialService.getVerifiableCredentialResponse(
                        testBearerAccessToken,
                        testPassportIssuer,
                        testApiKey,
                        CREDENTIAL_ISSUER_ID))
                .thenReturn(
                        VerifiableCredentialResponse.builder()
                                .userId("mismatched-user-id")
                                .credentialStatus(VerifiableCredentialStatus.PENDING)
                                .build());

        mockServiceCalls(makeTestIpvSessionItem(TEST_IPV_SESSION_ID));

        Map<String, Object> output = handler.handleRequest(testInput, context);

        assertEquals("/journey/error", output.get("journey"));

        verify(criResponseService, times(0)).persistCriResponse(any(), any(), any(), any());

        verifyPersistedVisitedCredentialIssuerDetails(
                CREDENTIAL_ISSUER_ID, false, OAuth2Error.SERVER_ERROR_CODE);
    }

    private void mockServiceCallsAndSessionItem() {
        mockServiceCalls();
        when(ipvSessionItem.getIpvSessionId()).thenReturn(testSessionId);
    }

    private void mockServiceCalls() {
        when(configService.getCredentialIssuerActiveConnectionConfig(CREDENTIAL_ISSUER_ID))
                .thenReturn(testPassportIssuer);
        when(configService.getSsmParameter(COMPONENT_ID)).thenReturn(testComponentId);
        when(configService.getCriPrivateApiKey(anyString())).thenReturn(testApiKey);
        when(ipvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);
        when(criOAuthSessionService.getCriOauthSessionItem(any())).thenReturn(criOAuthSessionItem);
        when(mockClientOAuthSessionService.getClientOAuthSession(any()))
                .thenReturn(getClientOAuthSessionItem());
    }

    private void mockServiceCalls(IpvSessionItem testIpvSessionItem) {
        when(configService.getCredentialIssuerActiveConnectionConfig(CREDENTIAL_ISSUER_ID))
                .thenReturn(testPassportIssuer);
        when(configService.getSsmParameter(COMPONENT_ID)).thenReturn(testComponentId);
        when(configService.getCriPrivateApiKey(anyString())).thenReturn(testApiKey);
        when(ipvSessionService.getIpvSession(anyString())).thenReturn(testIpvSessionItem);
        when(criOAuthSessionService.getCriOauthSessionItem(any())).thenReturn(criOAuthSessionItem);
        when(mockClientOAuthSessionService.getClientOAuthSession(any()))
                .thenReturn(getClientOAuthSessionItem());
    }

    private ClientOAuthSessionItem getClientOAuthSessionItem() {
        return ClientOAuthSessionItem.builder()
                .clientOAuthSessionId(SecureTokenHelper.generate())
                .responseType("code")
                .state(TEST_CLIENT_OAUTH_STATE)
                .redirectUri("https://example.com/redirect")
                .govukSigninJourneyId("test-journey-id")
                .userId("test-user-id")
                .build();
    }

    private void verifyPersistedCriResponse(
            String expectedUserId,
            String expectedCredentialIssuerId,
            String expectedIssuerResponse,
            String expectedOauthState) {
        ArgumentCaptor<String> persistedUserIdCaptor = ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> persistedCredentialIssuerIdCaptor =
                ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> persistedIssuerResponseCaptor =
                ArgumentCaptor.forClass(String.class);
        ArgumentCaptor<String> persistedOAuthStateCaptor = ArgumentCaptor.forClass(String.class);
        verify(criResponseService, times(1))
                .persistCriResponse(
                        persistedUserIdCaptor.capture(),
                        persistedCredentialIssuerIdCaptor.capture(),
                        persistedIssuerResponseCaptor.capture(),
                        persistedOAuthStateCaptor.capture());
        assertEquals(expectedUserId, persistedUserIdCaptor.getAllValues().get(0));
        assertEquals(
                expectedCredentialIssuerId,
                persistedCredentialIssuerIdCaptor.getAllValues().get(0));
        assertEquals(expectedIssuerResponse, persistedIssuerResponseCaptor.getAllValues().get(0));
        assertEquals(expectedOauthState, persistedOAuthStateCaptor.getAllValues().get(0));
    }

    private void verifyPersistedVisitedCredentialIssuerDetails(
            String expectedCredentialIssuerId,
            boolean expectedIsReturnedWithVc,
            String expectedOauthError) {
        ArgumentCaptor<IpvSessionItem> persistedIpvSessionItemCaptor =
                ArgumentCaptor.forClass(IpvSessionItem.class);
        verify(ipvSessionService, times(1))
                .updateIpvSession(persistedIpvSessionItemCaptor.capture());
        assertEquals(
                1,
                persistedIpvSessionItemCaptor
                        .getAllValues()
                        .get(0)
                        .getVisitedCredentialIssuerDetails()
                        .size());
        VisitedCredentialIssuerDetailsDto visitedCredentialIssuerDetails =
                persistedIpvSessionItemCaptor
                        .getAllValues()
                        .get(0)
                        .getVisitedCredentialIssuerDetails()
                        .get(0);
        assertEquals(expectedCredentialIssuerId, visitedCredentialIssuerDetails.getCriId());
        assertEquals(expectedIsReturnedWithVc, visitedCredentialIssuerDetails.isReturnedWithVc());
        assertEquals(expectedOauthError, visitedCredentialIssuerDetails.getOauthError());
    }

    private IpvSessionItem makeTestIpvSessionItem(String ipvSessionId) {
        final IpvSessionItem testIpvSessionItem = new IpvSessionItem();
        testIpvSessionItem.setIpvSessionId(ipvSessionId);
        return testIpvSessionItem;
    }
}
