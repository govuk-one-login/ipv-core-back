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
import uk.gov.di.ipv.core.library.credentialissuer.CredentialIssuerService;
import uk.gov.di.ipv.core.library.credentialissuer.exceptions.CredentialIssuerException;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.dto.CredentialIssuerConfig;
import uk.gov.di.ipv.core.library.exceptions.CiPutException;
import uk.gov.di.ipv.core.library.exceptions.SqsException;
import uk.gov.di.ipv.core.library.helpers.SecureTokenHelper;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.CriOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.CiStorageService;
import uk.gov.di.ipv.core.library.service.ClientOAuthSessionDetailsService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.CriOAuthSessionService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.retrievecricredential.validation.VerifiableCredentialJwtValidator;

import java.net.URI;
import java.net.URISyntaxException;
import java.text.ParseException;
import java.util.Collections;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.ADDRESS_CRI_ID;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.COMPONENT_ID;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.RSA_ENCRYPTION_PUBLIC_JWK;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.SIGNED_ADDRESS_VC;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.SIGNED_CONTRA_INDICATORS;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.SIGNED_VC_1;

@ExtendWith(MockitoExtension.class)
class RetrieveCriCredentialHandlerTest {
    private static final String ACCESS_TOKEN = "Bearer dGVzdAo=";
    private static final String CREDENTIAL_ISSUER_ID = "PassportIssuer";
    private static final String ADDRESS_CRI_JOURNEY_ID = "address";
    private static final String TEST_USER_ID = "test-user-id";
    private static final String TEST_STATE = "test-state";
    private static final String TEST_IP_ADDRESS = "192.168.1.100";
    private static final String CODE = "code";
    private static final String MESSAGE = "message";
    private static final String STATUS_CODE = "statusCode";
    private static final String passportIssuerId = CREDENTIAL_ISSUER_ID;

    @Mock private Context context;
    @Mock private CredentialIssuerService credentialIssuerService;
    @Mock private AuditService auditService;
    @Mock private static ConfigService configService;
    @Mock private VerifiableCredentialJwtValidator verifiableCredentialJwtValidator;
    @Mock private IpvSessionService ipvSessionService;
    @Mock private IpvSessionItem ipvSessionItem;
    @Mock private CiStorageService ciStorageService;
    @Mock private CriOAuthSessionService criOAuthSessionService;
    @Mock private ClientOAuthSessionDetailsService mockClientOAuthSessionService;
    private static CriOAuthSessionItem criOAuthSessionItem;
    @InjectMocks private RetrieveCriCredentialHandler handler;

    private static BearerAccessToken testBearerAccessToken;
    private static CredentialIssuerConfig testPassportIssuer;
    private static Map<String, String> testInput;
    private static final String testSessionId = SecureTokenHelper.generate();
    private static final String testApiKey = "test-api-key";
    private static final String testComponentId = "https://ipv-core-test.example.com";
    private static CredentialIssuerConfig addressConfig = null;

    static {
        try {
            addressConfig =
                    new CredentialIssuerConfig(
                            "address",
                            "address",
                            new URI("http://example.com/token"),
                            new URI("http://example.com/credential"),
                            new URI("http://example.com/authorize"),
                            "ipv-core",
                            "test-jwk",
                            "test-encryption-jwk",
                            "test-audience",
                            new URI("http://example.com/redirect"));
        } catch (URISyntaxException e) {
            e.printStackTrace();
        }
    }

    @BeforeAll
    static void setUp() throws URISyntaxException, com.nimbusds.oauth2.sdk.ParseException {
        testPassportIssuer =
                new CredentialIssuerConfig(
                        CREDENTIAL_ISSUER_ID,
                        "any",
                        new URI("https://www.example.com"),
                        new URI("https://www.example.com/credential"),
                        new URI("https://www.example.com/authorize"),
                        "ipv-core",
                        "{}",
                        RSA_ENCRYPTION_PUBLIC_JWK,
                        "test-audience",
                        new URI("https://www.example.com/credential-issuers/callback/criId"));

        testBearerAccessToken = BearerAccessToken.parse(ACCESS_TOKEN);

        testInput = Map.of("ipvSessionId", testSessionId, "ipAddress", TEST_IP_ADDRESS);

        criOAuthSessionItem =
                CriOAuthSessionItem.builder()
                        .criOAuthSessionId(TEST_STATE)
                        .criId(CREDENTIAL_ISSUER_ID)
                        .accessToken(ACCESS_TOKEN)
                        .build();
    }

    @Test
    void shouldReturnJourneyResponseOnSuccessfulRequest() throws Exception {
        when(ipvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);
        when(credentialIssuerService.getVerifiableCredential(
                        testBearerAccessToken, testPassportIssuer, testApiKey))
                .thenReturn(List.of(SignedJWT.parse(SIGNED_VC_1)));

        mockServiceCallsAndSessionItem();

        Map<String, Object> output = handler.handleRequest(testInput, context);

        ArgumentCaptor<AuditEvent> auditEventCaptor = ArgumentCaptor.forClass(AuditEvent.class);
        verify(auditService, times(1)).sendAuditEvent(auditEventCaptor.capture());
        List<AuditEvent> auditEvents = auditEventCaptor.getAllValues();
        assertEquals(AuditEventTypes.IPV_VC_RECEIVED, auditEvents.get(0).getEventName());

        verify(verifiableCredentialJwtValidator)
                .validate(any(SignedJWT.class), eq(testPassportIssuer), eq(TEST_USER_ID));

        assertEquals("/journey/next", output.get("journey"));
        verify(criOAuthSessionService, times(1)).getCriOauthSessionItem(any());
    }

    @Test
    void shouldUpdateSessionWithDetailsOfVisitedCri() throws ParseException {
        when(configService.getCredentialIssuerActiveConnectionConfig(CREDENTIAL_ISSUER_ID))
                .thenReturn(testPassportIssuer);
        when(configService.getSsmParameter(COMPONENT_ID)).thenReturn(testComponentId);
        when(configService.getCriPrivateApiKey(anyString())).thenReturn(testApiKey);
        when(credentialIssuerService.getVerifiableCredential(
                        testBearerAccessToken, testPassportIssuer, testApiKey))
                .thenReturn(List.of(SignedJWT.parse(SIGNED_VC_1)));

        IpvSessionItem ipvSessionItem = new IpvSessionItem();
        ipvSessionItem.setIpvSessionId("someIpvSessionId");
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
        mockServiceCallsAndSessionItem();

        when(credentialIssuerService.getVerifiableCredential(any(), any(), anyString()))
                .thenThrow(
                        new CredentialIssuerException(
                                HTTPResponse.SC_SERVER_ERROR,
                                ErrorResponse.FAILED_TO_GET_CREDENTIAL_FROM_ISSUER));

        Map<String, Object> output = handler.handleRequest(testInput, context);

        assertEquals("/journey/error", output.get("journey"));
    }

    @Test
    void shouldReturnErrorJourneyResponseIfSqsExceptionIsThrown() throws Exception {
        mockServiceCallsAndSessionItem();
        when(credentialIssuerService.getVerifiableCredential(
                        testBearerAccessToken, testPassportIssuer, testApiKey))
                .thenReturn(List.of(SignedJWT.parse(SIGNED_VC_1)));

        doThrow(new SqsException("Test sqs error"))
                .when(auditService)
                .sendAuditEvent(any(AuditEvent.class));

        Map<String, Object> output = handler.handleRequest(testInput, context);

        assertEquals("/journey/error", output.get("journey"));
    }

    @Test
    void shouldReturnErrorJourneyIfVCFailsValidation() throws Exception {
        when(credentialIssuerService.getVerifiableCredential(
                        testBearerAccessToken, testPassportIssuer, testApiKey))
                .thenReturn(List.of(SignedJWT.parse(SIGNED_VC_1)));

        mockServiceCallsAndSessionItem();

        doThrow(
                        new CredentialIssuerException(
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
        when(credentialIssuerService.getVerifiableCredential(
                        testBearerAccessToken, testPassportIssuer, testApiKey))
                .thenReturn(List.of(SignedJWT.parse(SIGNED_CONTRA_INDICATORS)));
        mockServiceCallsAndSessionItem();

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
    }

    @Test
    void shouldSendIpvVcReceivedAuditEventWhenVcEvidenceIsMissing() throws Exception {
        when(credentialIssuerService.getVerifiableCredential(
                        testBearerAccessToken, testPassportIssuer, testApiKey))
                .thenReturn(List.of(SignedJWT.parse(SIGNED_ADDRESS_VC)));
        when(configService.getSsmParameter(ADDRESS_CRI_ID)).thenReturn(ADDRESS_CRI_JOURNEY_ID);
        when(configService.getCredentialIssuerActiveConnectionConfig(ADDRESS_CRI_JOURNEY_ID))
                .thenReturn(addressConfig);
        mockServiceCallsAndSessionItem();

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
        when(credentialIssuerService.getVerifiableCredential(
                        testBearerAccessToken, testPassportIssuer, testApiKey))
                .thenReturn(List.of(SignedJWT.parse(SIGNED_ADDRESS_VC)));
        when(configService.getSsmParameter(ADDRESS_CRI_ID)).thenReturn(ADDRESS_CRI_JOURNEY_ID);
        when(configService.getCredentialIssuerActiveConnectionConfig(CREDENTIAL_ISSUER_ID))
                .thenReturn(testPassportIssuer);
        when(configService.getCredentialIssuerActiveConnectionConfig(ADDRESS_CRI_JOURNEY_ID))
                .thenReturn(addressConfig);
        when(configService.getSsmParameter(COMPONENT_ID)).thenReturn(testComponentId);
        when(configService.getCriPrivateApiKey(anyString())).thenReturn(testApiKey);
        when(mockClientOAuthSessionService.getClientOAuthSession(any()))
                .thenReturn(getClientOAuthSessionItem());

        IpvSessionItem ipvSessionItem = new IpvSessionItem();
        when(criOAuthSessionService.getCriOauthSessionItem(any())).thenReturn(criOAuthSessionItem);
        when(ipvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);

        doThrow(new CiPutException("Lambda execution failed"))
                .when(ciStorageService)
                .submitVC(any(SignedJWT.class), anyString(), anyString());

        handler.handleRequest(testInput, context);

        verify(credentialIssuerService, never()).persistUserCredentials(any(), any(), any());

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

    private void mockServiceCallsAndSessionItem() {
        when(configService.getCredentialIssuerActiveConnectionConfig(CREDENTIAL_ISSUER_ID))
                .thenReturn(testPassportIssuer);
        when(configService.getSsmParameter(COMPONENT_ID)).thenReturn(testComponentId);
        when(configService.getCriPrivateApiKey(anyString())).thenReturn(testApiKey);
        when(ipvSessionService.getIpvSession(anyString())).thenReturn(ipvSessionItem);
        when(criOAuthSessionService.getCriOauthSessionItem(any())).thenReturn(criOAuthSessionItem);
        when(ipvSessionItem.getIpvSessionId()).thenReturn(testSessionId);
        when(mockClientOAuthSessionService.getClientOAuthSession(any()))
                .thenReturn(getClientOAuthSessionItem());
    }

    private ClientOAuthSessionItem getClientOAuthSessionItem() {
        ClientOAuthSessionItem clientOAuthSessionItem =
                ClientOAuthSessionItem.builder()
                        .clientOAuthSessionId(SecureTokenHelper.generate())
                        .responseType("code")
                        .state("test-state")
                        .redirectUri("https://example.com/redirect")
                        .govukSigninJourneyId("test-journey-id")
                        .userId("test-user-id")
                        .build();
        return clientOAuthSessionItem;
    }
}
