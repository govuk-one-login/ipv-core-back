package uk.gov.di.ipv.core.checkexistingidentity;

import com.amazonaws.services.lambda.runtime.Context;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.SignedJWT;
import org.apache.http.HttpStatus;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.InOrder;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.auditing.AuditEvent;
import uk.gov.di.ipv.core.library.auditing.AuditEventTypes;
import uk.gov.di.ipv.core.library.cimit.exception.CiRetrievalException;
import uk.gov.di.ipv.core.library.domain.ContraIndicators;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.JourneyErrorResponse;
import uk.gov.di.ipv.core.library.domain.JourneyRequest;
import uk.gov.di.ipv.core.library.domain.JourneyResponse;
import uk.gov.di.ipv.core.library.domain.cimitvc.ContraIndicator;
import uk.gov.di.ipv.core.library.domain.cimitvc.Mitigation;
import uk.gov.di.ipv.core.library.dto.ContraIndicatorMitigationDetailsDto;
import uk.gov.di.ipv.core.library.dto.CredentialIssuerConfig;
import uk.gov.di.ipv.core.library.exceptions.ConfigException;
import uk.gov.di.ipv.core.library.exceptions.CredentialParseException;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.core.library.exceptions.SqsException;
import uk.gov.di.ipv.core.library.exceptions.UnrecognisedCiException;
import uk.gov.di.ipv.core.library.gpg45.Gpg45ProfileEvaluator;
import uk.gov.di.ipv.core.library.gpg45.enums.Gpg45Profile;
import uk.gov.di.ipv.core.library.gpg45.exception.UnknownEvidenceTypeException;
import uk.gov.di.ipv.core.library.helpers.SecureTokenHelper;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.CriResponseItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.VcStoreItem;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.CiMitService;
import uk.gov.di.ipv.core.library.service.ClientOAuthSessionDetailsService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.CriResponseService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.service.UserIdentityService;

import java.net.URI;
import java.net.URISyntaxException;
import java.text.ParseException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.checkexistingidentity.CheckExistingIdentityHandler.VOT_P2;
import static uk.gov.di.ipv.core.library.config.CoreFeatureFlag.RESET_IDENTITY;
import static uk.gov.di.ipv.core.library.domain.CriConstants.F2F_CRI;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.M1A_ADDRESS_VC;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.M1A_F2F_VC;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.M1A_FRAUD_VC;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.M1A_PASSPORT_VC;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.M1A_VERIFICATION_VC;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.M1B_DCMAW_VC;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.VC_PASSPORT_NON_DCMAW_SUCCESSFUL;
import static uk.gov.di.ipv.core.library.journeyuris.JourneyUris.JOURNEY_ERROR_PATH;
import static uk.gov.di.ipv.core.library.journeyuris.JourneyUris.JOURNEY_F2F_FAIL_PATH;
import static uk.gov.di.ipv.core.library.journeyuris.JourneyUris.JOURNEY_FAIL_WITH_CI_PATH;
import static uk.gov.di.ipv.core.library.journeyuris.JourneyUris.JOURNEY_PENDING_PATH;
import static uk.gov.di.ipv.core.library.journeyuris.JourneyUris.JOURNEY_RESET_IDENTITY_PATH;
import static uk.gov.di.ipv.core.library.journeyuris.JourneyUris.JOURNEY_REUSE_PATH;

@ExtendWith(MockitoExtension.class)
class CheckExistingIdentityHandlerTest {
    private static final String TEST_SESSION_ID = "test-session-id";
    private static final String TEST_USER_ID = "test-user-id";
    private static final String TEST_JOURNEY_ID = "test-journey-id";
    private static final String TEST_CLIENT_SOURCE_IP = "test-client-source-ip";
    private static final String TEST_FEATURE_SET = "test-feature-set";
    private static final String TEST_CLIENT_OAUTH_SESSION_ID = SecureTokenHelper.generate();
    private static final String TEST_JOURNEY = "journey/check-existing-identity";
    private static final List<String> CREDENTIALS =
            List.of(
                    M1A_PASSPORT_VC,
                    M1A_ADDRESS_VC,
                    M1A_FRAUD_VC,
                    M1A_VERIFICATION_VC,
                    M1B_DCMAW_VC);
    private static CredentialIssuerConfig addressConfig = null;
    private static CredentialIssuerConfig claimedIdentityConfig = null;
    private static final List<SignedJWT> PARSED_CREDENTIALS = new ArrayList<>();
    private static final List<Gpg45Profile> ACCEPTED_PROFILES =
            List.of(Gpg45Profile.M1A, Gpg45Profile.M1B, Gpg45Profile.M2B);
    private static final JourneyResponse JOURNEY_REUSE = new JourneyResponse(JOURNEY_REUSE_PATH);
    private static final JourneyResponse JOURNEY_RESET_IDENTITY =
            new JourneyResponse(JOURNEY_RESET_IDENTITY_PATH);
    private static final JourneyResponse JOURNEY_PENDING =
            new JourneyResponse(JOURNEY_PENDING_PATH);
    private static final JourneyResponse JOURNEY_F2F_FAIL =
            new JourneyResponse(JOURNEY_F2F_FAIL_PATH);
    private static final ObjectMapper mapper = new ObjectMapper();

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
                            true,
                            false);

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
                            true,
                            false);
        } catch (URISyntaxException e) {
            e.printStackTrace();
        }
    }

    @Mock private Context context;
    @Mock private UserIdentityService userIdentityService;
    @Mock private CriResponseService criResponseService;
    @Mock private IpvSessionService ipvSessionService;
    @Mock private Gpg45ProfileEvaluator gpg45ProfileEvaluator;
    @Mock private ConfigService configService;
    @Mock private AuditService auditService;
    @Mock private ClientOAuthSessionDetailsService clientOAuthSessionDetailsService;
    @Mock private CiMitService ciMitService;
    @InjectMocks private CheckExistingIdentityHandler checkExistingIdentityHandler;

    @Spy private IpvSessionItem ipvSessionItem;
    private JourneyRequest event;
    private ClientOAuthSessionItem clientOAuthSessionItem;

    @BeforeAll
    static void setUp() throws Exception {
        for (String cred : CREDENTIALS) {
            PARSED_CREDENTIALS.add(SignedJWT.parse(cred));
        }
    }

    @BeforeEach
    void setUpEach() {
        event =
                JourneyRequest.builder()
                        .ipvSessionId(TEST_SESSION_ID)
                        .ipAddress(TEST_CLIENT_SOURCE_IP)
                        .clientOAuthSessionId(TEST_CLIENT_SOURCE_IP)
                        .journey(TEST_JOURNEY)
                        .featureSet(TEST_FEATURE_SET)
                        .build();

        ipvSessionItem.setClientOAuthSessionId(TEST_CLIENT_OAUTH_SESSION_ID);
        ipvSessionItem.setIpvSessionId(TEST_SESSION_ID);
        ipvSessionItem.setContraIndicatorMitigationDetails(
                List.of(new ContraIndicatorMitigationDetailsDto("A01")));

        clientOAuthSessionItem =
                ClientOAuthSessionItem.builder()
                        .clientOAuthSessionId(TEST_CLIENT_OAUTH_SESSION_ID)
                        .state("test-state")
                        .responseType("code")
                        .redirectUri("https://example.com/redirect")
                        .govukSigninJourneyId("test-journey-id")
                        .userId(TEST_USER_ID)
                        .clientId("test-client")
                        .govukSigninJourneyId(TEST_JOURNEY_ID)
                        .reproveIdentity(false)
                        .build();
    }

    @Test
    void shouldReturnJourneyReuseResponseIfScoresSatisfyM1AGpg45Profile() throws Exception {
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(userIdentityService.areVcsCorrelated(TEST_USER_ID)).thenReturn(true);
        when(gpg45ProfileEvaluator.parseCredentials(any())).thenReturn(PARSED_CREDENTIALS);
        when(gpg45ProfileEvaluator.getFirstMatchingProfile(any(), eq(ACCEPTED_PROFILES)))
                .thenReturn(Optional.of(Gpg45Profile.M1A));
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(configService.enabled(RESET_IDENTITY.getName())).thenReturn(false);

        JourneyResponse journeyResponse =
                toResponseClass(
                        checkExistingIdentityHandler.handleRequest(event, context),
                        JourneyResponse.class);

        assertEquals(JOURNEY_REUSE, journeyResponse);

        ArgumentCaptor<AuditEvent> auditEventArgumentCaptor =
                ArgumentCaptor.forClass(AuditEvent.class);
        verify(auditService, times(2)).sendAuditEvent(auditEventArgumentCaptor.capture());
        assertEquals(
                AuditEventTypes.IPV_GPG45_PROFILE_MATCHED,
                auditEventArgumentCaptor.getAllValues().get(0).getEventName());
        assertEquals(
                AuditEventTypes.IPV_IDENTITY_REUSE_COMPLETE,
                auditEventArgumentCaptor.getAllValues().get(1).getEventName());
        verify(clientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());

        InOrder inOrder = inOrder(ipvSessionItem, ipvSessionService);
        inOrder.verify(ipvSessionItem).setVot(VOT_P2);
        inOrder.verify(ipvSessionService).updateIpvSession(ipvSessionItem);
        inOrder.verify(ipvSessionItem, never()).setVot(any());
        assertEquals(VOT_P2, ipvSessionItem.getVot());
    }

    @Test
    void shouldReturnJourneyResetIdentityIfResetIdentityFeatureFlagIsEnabled() throws Exception {
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(userIdentityService.getUserIssuedCredentials(TEST_USER_ID)).thenReturn(CREDENTIALS);
        when(criResponseService.getFaceToFaceRequest(TEST_USER_ID)).thenReturn(null);
        when(userIdentityService.areVcsCorrelated(TEST_USER_ID)).thenReturn(true);
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(configService.enabled(RESET_IDENTITY.getName())).thenReturn(true);

        JourneyResponse journeyResponse =
                toResponseClass(
                        checkExistingIdentityHandler.handleRequest(event, context),
                        JourneyResponse.class);

        assertEquals(JOURNEY_RESET_IDENTITY, journeyResponse);

        ArgumentCaptor<AuditEvent> auditEventArgumentCaptor =
                ArgumentCaptor.forClass(AuditEvent.class);
        verify(auditService, never()).sendAuditEvent(auditEventArgumentCaptor.capture());
    }

    @Test
    void shouldReturnJourneyResetIdentityIfReApproveFlagIsReceived() throws Exception {
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        clientOAuthSessionItem.setReproveIdentity(true);

        JourneyResponse journeyResponse =
                toResponseClass(
                        checkExistingIdentityHandler.handleRequest(event, context),
                        JourneyResponse.class);

        assertEquals(JOURNEY_RESET_IDENTITY, journeyResponse);

        ArgumentCaptor<AuditEvent> auditEventArgumentCaptor =
                ArgumentCaptor.forClass(AuditEvent.class);
        verify(auditService, never()).sendAuditEvent(auditEventArgumentCaptor.capture());
    }

    @Test
    void shouldReturnJourneyReuseResponseIfScoresSatisfyM1BGpg45Profile() throws Exception {
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(userIdentityService.getUserIssuedCredentials(TEST_USER_ID)).thenReturn(CREDENTIALS);
        when(criResponseService.getFaceToFaceRequest(TEST_USER_ID)).thenReturn(null);
        when(userIdentityService.areVcsCorrelated(TEST_USER_ID)).thenReturn(true);
        when(gpg45ProfileEvaluator.getFirstMatchingProfile(any(), eq(ACCEPTED_PROFILES)))
                .thenReturn(Optional.of(Gpg45Profile.M1B));
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(configService.enabled(RESET_IDENTITY.getName())).thenReturn(false);

        JourneyResponse journeyResponse =
                toResponseClass(
                        checkExistingIdentityHandler.handleRequest(event, context),
                        JourneyResponse.class);

        assertEquals(JOURNEY_REUSE, journeyResponse);

        ArgumentCaptor<AuditEvent> auditEventArgumentCaptor =
                ArgumentCaptor.forClass(AuditEvent.class);
        verify(auditService, times(2)).sendAuditEvent(auditEventArgumentCaptor.capture());
        assertEquals(
                AuditEventTypes.IPV_IDENTITY_REUSE_COMPLETE,
                auditEventArgumentCaptor.getValue().getEventName());
        verify(clientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());

        verify(ipvSessionService, times(1)).updateIpvSession(ipvSessionItem);

        InOrder inOrder = inOrder(ipvSessionItem, ipvSessionService);
        inOrder.verify(ipvSessionItem).setVot(VOT_P2);
        inOrder.verify(ipvSessionService).updateIpvSession(ipvSessionItem);
        inOrder.verify(ipvSessionItem, never()).setVot(any());
        assertEquals(VOT_P2, ipvSessionItem.getVot());
    }

    @Test
    void shouldReturnJourneyResetIdentityResponseIfScoresDoNotSatisfyM1AGpg45Profile()
            throws Exception {
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(userIdentityService.getUserIssuedCredentials(TEST_USER_ID)).thenReturn(CREDENTIALS);
        when(userIdentityService.areVcsCorrelated(TEST_USER_ID)).thenReturn(true);
        when(criResponseService.getFaceToFaceRequest(TEST_USER_ID)).thenReturn(null);
        when(gpg45ProfileEvaluator.getFirstMatchingProfile(any(), eq(ACCEPTED_PROFILES)))
                .thenReturn(Optional.empty());
        when(gpg45ProfileEvaluator.parseCredentials(any())).thenCallRealMethod();
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        JourneyResponse journeyResponse =
                toResponseClass(
                        checkExistingIdentityHandler.handleRequest(event, context),
                        JourneyResponse.class);

        assertEquals(JOURNEY_RESET_IDENTITY, journeyResponse);

        ArgumentCaptor<AuditEvent> auditEventArgumentCaptor =
                ArgumentCaptor.forClass(AuditEvent.class);
        verify(auditService).sendAuditEvent(auditEventArgumentCaptor.capture());
        assertEquals(
                AuditEventTypes.IPV_IDENTITY_REUSE_RESET,
                auditEventArgumentCaptor.getValue().getEventName());
        verify(clientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());

        verify(ipvSessionItem, never()).setVot(any());
        assertNull(ipvSessionItem.getVot());
    }

    @Test
    void shouldNotSendAuditEventIfNewUser() throws Exception {
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(userIdentityService.getUserIssuedCredentials(TEST_USER_ID))
                .thenReturn(Collections.emptyList());
        when(criResponseService.getFaceToFaceRequest(TEST_USER_ID)).thenReturn(null);
        when(gpg45ProfileEvaluator.parseCredentials(any())).thenCallRealMethod();
        when(userIdentityService.areVcsCorrelated(TEST_USER_ID)).thenReturn(true);
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        JourneyResponse journeyResponse =
                toResponseClass(
                        checkExistingIdentityHandler.handleRequest(event, context),
                        JourneyResponse.class);

        assertEquals("/journey/next", journeyResponse.getJourney());

        ArgumentCaptor<AuditEvent> auditEventArgumentCaptor =
                ArgumentCaptor.forClass(AuditEvent.class);
        verify(auditService, never()).sendAuditEvent(auditEventArgumentCaptor.capture());
        verify(clientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());

        verify(ipvSessionService, never()).updateIpvSession(any());

        verify(ipvSessionItem, never()).setVot(any());
        assertNull(ipvSessionItem.getVot());
    }

    @Test
    void shouldReturn400IfSessionIdNotInHeader() {
        JourneyRequest eventWithoutHeaders = JourneyRequest.builder().build();

        JourneyErrorResponse journeyResponse =
                toResponseClass(
                        checkExistingIdentityHandler.handleRequest(eventWithoutHeaders, context),
                        JourneyErrorResponse.class);

        assertEquals("/journey/error", journeyResponse.getJourney());

        assertEquals(HttpStatus.SC_BAD_REQUEST, journeyResponse.getStatusCode());
        assertEquals(ErrorResponse.MISSING_IPV_SESSION_ID.getCode(), journeyResponse.getCode());
        assertEquals(
                ErrorResponse.MISSING_IPV_SESSION_ID.getMessage(), journeyResponse.getMessage());
        verify(clientOAuthSessionDetailsService, times(0)).getClientOAuthSession(any());

        verify(ipvSessionService, never()).updateIpvSession(any());

        verify(ipvSessionItem, never()).setVot(any());
        assertNull(ipvSessionItem.getVot());
    }

    @Test
    void shouldReturnPendingResponseIfFaceToFaceVerificationIsPending() {
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(userIdentityService.getVcStoreItem(TEST_USER_ID, F2F_CRI)).thenReturn(null);
        CriResponseItem criResponseItem =
                createCriResponseStoreItem(
                        TEST_USER_ID, F2F_CRI, VC_PASSPORT_NON_DCMAW_SUCCESSFUL, Instant.now());
        when(criResponseService.getFaceToFaceRequest(TEST_USER_ID)).thenReturn(criResponseItem);
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        JourneyResponse journeyResponse =
                toResponseClass(
                        checkExistingIdentityHandler.handleRequest(event, context),
                        JourneyResponse.class);

        assertEquals(JOURNEY_PENDING, journeyResponse);

        verify(ipvSessionService, never()).updateIpvSession(any());

        verify(ipvSessionItem, never()).setVot(any());
        assertNull(ipvSessionItem.getVot());
    }

    @Test
    void shouldReturnFailResponseIfFaceToFaceVerificationIsError() {
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(userIdentityService.getVcStoreItem(TEST_USER_ID, F2F_CRI)).thenReturn(null);
        CriResponseItem criResponseItem =
                createCriErrorResponseStoreItem(
                        TEST_USER_ID, F2F_CRI, VC_PASSPORT_NON_DCMAW_SUCCESSFUL, Instant.now());
        when(criResponseService.getFaceToFaceRequest(TEST_USER_ID)).thenReturn(criResponseItem);
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        JourneyResponse journeyResponse =
                toResponseClass(
                        checkExistingIdentityHandler.handleRequest(event, context),
                        JourneyResponse.class);

        assertEquals(JOURNEY_F2F_FAIL, journeyResponse);

        verify(ipvSessionService, never()).updateIpvSession(any());

        verify(ipvSessionItem, never()).setVot(any());
        assertNull(ipvSessionItem.getVot());
    }

    @Test
    void shouldReturnFailResponseForFaceToFaceVerificationIfNoMatchedProfile()
            throws HttpResponseExceptionWithErrorBody, CredentialParseException, SqsException {
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(userIdentityService.getVcStoreItem(TEST_USER_ID, F2F_CRI))
                .thenReturn(createVcStoreItem(F2F_CRI, M1A_F2F_VC));
        CriResponseItem criResponseItem =
                createCriResponseStoreItem(
                        TEST_USER_ID, F2F_CRI, VC_PASSPORT_NON_DCMAW_SUCCESSFUL, Instant.now());
        when(criResponseService.getFaceToFaceRequest(TEST_USER_ID)).thenReturn(criResponseItem);
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(userIdentityService.areVcsCorrelated(any())).thenReturn(true);

        JourneyResponse journeyResponse =
                toResponseClass(
                        checkExistingIdentityHandler.handleRequest(event, context),
                        JourneyResponse.class);

        ArgumentCaptor<AuditEvent> auditEventArgumentCaptor =
                ArgumentCaptor.forClass(AuditEvent.class);
        verify(auditService, times(1)).sendAuditEvent(auditEventArgumentCaptor.capture());
        assertEquals(
                AuditEventTypes.IPV_F2F_PROFILE_NOT_MET_FAIL,
                auditEventArgumentCaptor.getAllValues().get(0).getEventName());

        assertEquals(JOURNEY_F2F_FAIL, journeyResponse);

        verify(ipvSessionService, never()).updateIpvSession(any());

        verify(ipvSessionItem, never()).setVot(any());
        assertNull(ipvSessionItem.getVot());
    }

    @Test
    void shouldReturnFailResponseForFaceToFaceIfNamesDoNotCorrelate() throws Exception {
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(userIdentityService.getVcStoreItem(TEST_USER_ID, F2F_CRI))
                .thenReturn(createVcStoreItem(F2F_CRI, M1A_F2F_VC));
        CriResponseItem criResponseItem =
                createCriResponseStoreItem(
                        TEST_USER_ID, F2F_CRI, VC_PASSPORT_NON_DCMAW_SUCCESSFUL, Instant.now());
        when(criResponseService.getFaceToFaceRequest(TEST_USER_ID)).thenReturn(criResponseItem);
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(userIdentityService.areVcsCorrelated(any())).thenReturn(false);

        JourneyResponse journeyResponse =
                toResponseClass(
                        checkExistingIdentityHandler.handleRequest(event, context),
                        JourneyResponse.class);

        ArgumentCaptor<AuditEvent> auditEventArgumentCaptor =
                ArgumentCaptor.forClass(AuditEvent.class);
        verify(auditService, times(1)).sendAuditEvent(auditEventArgumentCaptor.capture());
        assertEquals(
                AuditEventTypes.IPV_F2F_CORRELATION_FAIL,
                auditEventArgumentCaptor.getAllValues().get(0).getEventName());

        assertEquals(JOURNEY_F2F_FAIL, journeyResponse);

        verify(ipvSessionService, never()).updateIpvSession(any());

        verify(ipvSessionItem, never()).setVot(any());
        assertNull(ipvSessionItem.getVot());
    }

    @Test
    void shouldReturnFailResponseForFaceToFaceIfBirthDatesDoNotCorrelate() throws Exception {
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(userIdentityService.getVcStoreItem(TEST_USER_ID, F2F_CRI))
                .thenReturn(createVcStoreItem(F2F_CRI, M1A_F2F_VC));
        CriResponseItem criResponseItem =
                createCriResponseStoreItem(
                        TEST_USER_ID, F2F_CRI, VC_PASSPORT_NON_DCMAW_SUCCESSFUL, Instant.now());
        when(criResponseService.getFaceToFaceRequest(TEST_USER_ID)).thenReturn(criResponseItem);
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(userIdentityService.areVcsCorrelated(any())).thenReturn(true);

        JourneyResponse journeyResponse =
                toResponseClass(
                        checkExistingIdentityHandler.handleRequest(event, context),
                        JourneyResponse.class);

        assertEquals(JOURNEY_F2F_FAIL, journeyResponse);

        verify(ipvSessionService, never()).updateIpvSession(any());

        verify(ipvSessionItem, never()).setVot(any());
        assertNull(ipvSessionItem.getVot());
    }

    @Test
    void shouldResetIdentityIfDataDoesNotCorrelateAndNotF2F() throws Exception {
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(userIdentityService.getVcStoreItem(TEST_USER_ID, F2F_CRI)).thenReturn(null);
        when(criResponseService.getFaceToFaceRequest(TEST_USER_ID)).thenReturn(null);
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(userIdentityService.areVcsCorrelated(any())).thenReturn(false);

        JourneyResponse journeyResponse =
                toResponseClass(
                        checkExistingIdentityHandler.handleRequest(event, context),
                        JourneyResponse.class);

        assertEquals(JOURNEY_RESET_IDENTITY, journeyResponse);

        verify(ipvSessionService, never()).updateIpvSession(any());

        verify(ipvSessionItem, never()).setVot(any());
        assertNull(ipvSessionItem.getVot());
    }

    @Test
    void shouldReturn500IfNoVcStatusForIssuer() throws Exception {
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(userIdentityService.getVcStoreItem(TEST_USER_ID, F2F_CRI)).thenReturn(null);
        when(criResponseService.getFaceToFaceRequest(TEST_USER_ID)).thenReturn(null);
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(userIdentityService.areVcsCorrelated(any()))
                .thenThrow(new CredentialParseException("Oops"));

        JourneyErrorResponse journeyResponse =
                toResponseClass(
                        checkExistingIdentityHandler.handleRequest(event, context),
                        JourneyErrorResponse.class);

        assertEquals(HttpStatus.SC_INTERNAL_SERVER_ERROR, journeyResponse.getStatusCode());
        assertEquals(
                ErrorResponse.FAILED_TO_PARSE_SUCCESSFUL_VC_STORE_ITEMS.getCode(),
                journeyResponse.getCode());
        assertEquals(
                ErrorResponse.FAILED_TO_PARSE_SUCCESSFUL_VC_STORE_ITEMS.getMessage(),
                journeyResponse.getMessage());

        verify(ipvSessionService, never()).updateIpvSession(any());

        verify(ipvSessionItem, never()).setVot(any());
        assertNull(ipvSessionItem.getVot());
    }

    @Test
    void shouldReturn500IfFailedToParseCredentials() throws Exception {
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(userIdentityService.areVcsCorrelated(TEST_USER_ID)).thenReturn(true);
        when(gpg45ProfileEvaluator.buildScore(any())).thenThrow(new ParseException("Whoops", 0));
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        JourneyErrorResponse journeyResponse =
                toResponseClass(
                        checkExistingIdentityHandler.handleRequest(event, context),
                        JourneyErrorResponse.class);

        assertEquals("/journey/error", journeyResponse.getJourney());

        assertEquals(HttpStatus.SC_INTERNAL_SERVER_ERROR, journeyResponse.getStatusCode());
        assertEquals(
                ErrorResponse.FAILED_TO_PARSE_ISSUED_CREDENTIALS.getCode(),
                journeyResponse.getCode());
        assertEquals(
                ErrorResponse.FAILED_TO_PARSE_ISSUED_CREDENTIALS.getMessage(),
                journeyResponse.getMessage());

        verify(userIdentityService).getUserIssuedCredentials(TEST_USER_ID);
        verify(clientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());

        verify(ipvSessionService, never()).updateIpvSession(any());

        verify(ipvSessionItem, never()).setVot(any());
        assertNull(ipvSessionItem.getVot());
    }

    @Test
    void shouldReturn500IfCredentialOfUnknownType() throws Exception {
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(userIdentityService.areVcsCorrelated(TEST_USER_ID)).thenReturn(true);
        when(gpg45ProfileEvaluator.buildScore(any())).thenThrow(new UnknownEvidenceTypeException());
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        JourneyErrorResponse journeyResponse =
                toResponseClass(
                        checkExistingIdentityHandler.handleRequest(event, context),
                        JourneyErrorResponse.class);

        assertEquals("/journey/error", journeyResponse.getJourney());

        assertEquals(HttpStatus.SC_INTERNAL_SERVER_ERROR, journeyResponse.getStatusCode());
        assertEquals(
                ErrorResponse.FAILED_TO_DETERMINE_CREDENTIAL_TYPE.getCode(),
                journeyResponse.getCode());
        assertEquals(
                ErrorResponse.FAILED_TO_DETERMINE_CREDENTIAL_TYPE.getMessage(),
                journeyResponse.getMessage());

        verify(userIdentityService).getUserIssuedCredentials(TEST_USER_ID);
        verify(criResponseService).getFaceToFaceRequest(TEST_USER_ID);
        verify(clientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());

        verify(ipvSessionService, never()).updateIpvSession(any());

        verify(ipvSessionItem, never()).setVot(any());
        assertNull(ipvSessionItem.getVot());
    }

    @Test
    void shouldReturn500IfFailedToSendAuditEvent() throws Exception {
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(gpg45ProfileEvaluator.parseCredentials(any())).thenReturn(PARSED_CREDENTIALS);
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        doThrow(new SqsException("test error"))
                .when(auditService)
                .sendAuditEvent((AuditEvent) any());

        JourneyErrorResponse journeyResponse =
                toResponseClass(
                        checkExistingIdentityHandler.handleRequest(event, context),
                        JourneyErrorResponse.class);

        assertEquals("/journey/error", journeyResponse.getJourney());

        assertEquals(HttpStatus.SC_INTERNAL_SERVER_ERROR, journeyResponse.getStatusCode());
        assertEquals(ErrorResponse.FAILED_TO_SEND_AUDIT_EVENT.getCode(), journeyResponse.getCode());
        assertEquals(
                ErrorResponse.FAILED_TO_SEND_AUDIT_EVENT.getMessage(),
                journeyResponse.getMessage());
        verify(clientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());

        verify(ipvSessionItem, never()).setVot(any());
        assertNull(ipvSessionItem.getVot());
    }

    @Test
    void shouldReturn500IfCredentialParseExceptionFromAreVcsCorrelated() throws Exception {
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(userIdentityService.getVcStoreItem(TEST_USER_ID, F2F_CRI)).thenReturn(null);
        when(criResponseService.getFaceToFaceRequest(TEST_USER_ID)).thenReturn(null);
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(userIdentityService.areVcsCorrelated(any()))
                .thenThrow(
                        new CredentialParseException("Failed to parse successful VC Store items."));

        JourneyErrorResponse journeyResponse =
                toResponseClass(
                        checkExistingIdentityHandler.handleRequest(event, context),
                        JourneyErrorResponse.class);

        assertEquals(HttpStatus.SC_INTERNAL_SERVER_ERROR, journeyResponse.getStatusCode());
        assertEquals(
                ErrorResponse.FAILED_TO_PARSE_SUCCESSFUL_VC_STORE_ITEMS.getCode(),
                journeyResponse.getCode());
        assertEquals(
                ErrorResponse.FAILED_TO_PARSE_SUCCESSFUL_VC_STORE_ITEMS.getMessage(),
                journeyResponse.getMessage());

        verify(ipvSessionService, never()).updateIpvSession(any());

        verify(ipvSessionItem, never()).setVot(any());
        assertNull(ipvSessionItem.getVot());
    }

    @Test
    void shouldReturn500IfCredentialParseExceptionFromCheckBirthDateCorrelationInCredentials()
            throws Exception {
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(userIdentityService.getVcStoreItem(TEST_USER_ID, F2F_CRI)).thenReturn(null);
        when(criResponseService.getFaceToFaceRequest(TEST_USER_ID)).thenReturn(null);
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(userIdentityService.areVcsCorrelated(any()))
                .thenThrow(
                        new CredentialParseException("Failed to parse successful VC Store items."));

        JourneyErrorResponse journeyResponse =
                toResponseClass(
                        checkExistingIdentityHandler.handleRequest(event, context),
                        JourneyErrorResponse.class);

        assertEquals(HttpStatus.SC_INTERNAL_SERVER_ERROR, journeyResponse.getStatusCode());
        assertEquals(
                ErrorResponse.FAILED_TO_PARSE_SUCCESSFUL_VC_STORE_ITEMS.getCode(),
                journeyResponse.getCode());
        assertEquals(
                ErrorResponse.FAILED_TO_PARSE_SUCCESSFUL_VC_STORE_ITEMS.getMessage(),
                journeyResponse.getMessage());

        verify(ipvSessionService, never()).updateIpvSession(any());

        verify(ipvSessionItem, never()).setVot(any());
        assertNull(ipvSessionItem.getVot());
    }

    @Test
    void shouldReturnCiJourneyResponseIfPresent() throws Exception {
        var testCiCode = "TEST01";
        var testJourneyResponse = "/journey/test-response";
        var testContraIndicators =
                ContraIndicators.builder()
                        .contraIndicatorsMap(
                                Map.of(
                                        testCiCode,
                                        ContraIndicator.builder().code(testCiCode).build()))
                        .build();
        var testCimitConfig = Map.of(testCiCode, testJourneyResponse);

        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(ciMitService.getContraIndicatorsVC(
                        TEST_USER_ID, TEST_JOURNEY_ID, TEST_CLIENT_SOURCE_IP))
                .thenReturn(testContraIndicators);
        when(userIdentityService.isBreachingCiThreshold(testContraIndicators)).thenReturn(true);
        when(configService.getCimitConfig()).thenReturn(testCimitConfig);

        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        JourneyResponse response =
                toResponseClass(
                        checkExistingIdentityHandler.handleRequest(event, context),
                        JourneyResponse.class);

        assertEquals(testJourneyResponse, response.getJourney());
    }

    @Test
    void shouldNotReturnCiJourneyResponseForMitigatedCi() throws Exception {
        var testCiCode = "TEST01";
        var testJourneyResponse = "/journey/test-response";
        var testContraIndicators =
                ContraIndicators.builder()
                        .contraIndicatorsMap(
                                Map.of(
                                        testCiCode,
                                        ContraIndicator.builder()
                                                .code(testCiCode)
                                                .mitigation(List.of(Mitigation.builder().build()))
                                                .build()))
                        .build();
        var testCimitConfig = Map.of(testCiCode, testJourneyResponse);

        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(ciMitService.getContraIndicatorsVC(
                        TEST_USER_ID, TEST_JOURNEY_ID, TEST_CLIENT_SOURCE_IP))
                .thenReturn(testContraIndicators);
        when(userIdentityService.isBreachingCiThreshold(testContraIndicators)).thenReturn(true);
        when(configService.getCimitConfig()).thenReturn(testCimitConfig);

        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        JourneyResponse response =
                toResponseClass(
                        checkExistingIdentityHandler.handleRequest(event, context),
                        JourneyResponse.class);

        assertEquals(JOURNEY_FAIL_WITH_CI_PATH, response.getJourney());
    }

    @Test
    void shouldReturn500IfFailedToRetrieveCisFromStorageSystem() throws Exception {
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(ciMitService.getContraIndicatorsVC(anyString(), anyString(), anyString()))
                .thenThrow(CiRetrievalException.class);
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        JourneyErrorResponse response =
                toResponseClass(
                        checkExistingIdentityHandler.handleRequest(event, context),
                        JourneyErrorResponse.class);

        assertEquals(HttpStatus.SC_INTERNAL_SERVER_ERROR, response.getStatusCode());
        assertEquals(ErrorResponse.FAILED_TO_GET_STORED_CIS.getCode(), response.getCode());
        assertEquals(ErrorResponse.FAILED_TO_GET_STORED_CIS.getMessage(), response.getMessage());
        verify(clientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());
    }

    @Test
    void shouldReturn500IfFailedToGetCimitConfig() throws Exception {
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(userIdentityService.isBreachingCiThreshold(any())).thenReturn(true);
        when(configService.getCimitConfig())
                .thenThrow(new ConfigException("Failed to get cimit config"));

        JourneyErrorResponse response =
                toResponseClass(
                        checkExistingIdentityHandler.handleRequest(event, context),
                        JourneyErrorResponse.class);

        assertEquals(HttpStatus.SC_INTERNAL_SERVER_ERROR, response.getStatusCode());
        assertEquals(ErrorResponse.FAILED_TO_PARSE_CONFIG.getCode(), response.getCode());
        assertEquals(ErrorResponse.FAILED_TO_PARSE_CONFIG.getMessage(), response.getMessage());
        verify(clientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());
    }

    @Test
    void shouldReturn500IfUnrecognisedCiReceived() throws Exception {
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(ciMitService.getContraIndicatorsVC(
                        TEST_USER_ID, TEST_JOURNEY_ID, TEST_CLIENT_SOURCE_IP))
                .thenThrow(new UnrecognisedCiException("Unrecognised CI"));

        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        JourneyErrorResponse response =
                toResponseClass(
                        checkExistingIdentityHandler.handleRequest(event, context),
                        JourneyErrorResponse.class);

        assertEquals(JOURNEY_ERROR_PATH, response.getJourney());
        assertEquals(HttpStatus.SC_INTERNAL_SERVER_ERROR, response.getStatusCode());
        assertEquals(ErrorResponse.UNRECOGNISED_CI_CODE.getCode(), response.getCode());
        assertEquals(ErrorResponse.UNRECOGNISED_CI_CODE.getMessage(), response.getMessage());
    }

    private <T> T toResponseClass(Map<String, Object> handlerOutput, Class<T> responseClass) {
        return mapper.convertValue(handlerOutput, responseClass);
    }

    @Test
    void shouldReturnJourneyReuseResponseIfCheckRequiresAdditionalEvidenceResponseFalse()
            throws Exception {
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(userIdentityService.checkNameAndFamilyNameCorrelationInCredentials(TEST_USER_ID))
                .thenReturn(true);
        when(userIdentityService.checkBirthDateCorrelationInCredentials(TEST_USER_ID))
                .thenReturn(true);
        when(gpg45ProfileEvaluator.parseCredentials(any())).thenReturn(PARSED_CREDENTIALS);
        when(gpg45ProfileEvaluator.getFirstMatchingProfile(any(), eq(ACCEPTED_PROFILES)))
                .thenReturn(Optional.of(Gpg45Profile.M1A));
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(configService.enabled(RESET_IDENTITY.getName())).thenReturn(false);
        when(userIdentityService.checkRequiresAdditionalEvidence(TEST_USER_ID)).thenReturn(false);
        JourneyResponse journeyResponse =
                toResponseClass(
                        checkExistingIdentityHandler.handleRequest(event, context),
                        JourneyResponse.class);

        assertEquals(JOURNEY_REUSE, journeyResponse);

        ArgumentCaptor<AuditEvent> auditEventArgumentCaptor =
                ArgumentCaptor.forClass(AuditEvent.class);
        verify(auditService, times(2)).sendAuditEvent(auditEventArgumentCaptor.capture());
        assertEquals(
                AuditEventTypes.IPV_GPG45_PROFILE_MATCHED,
                auditEventArgumentCaptor.getAllValues().get(0).getEventName());
        assertEquals(
                AuditEventTypes.IPV_IDENTITY_REUSE_COMPLETE,
                auditEventArgumentCaptor.getAllValues().get(1).getEventName());
        verify(clientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());

        InOrder inOrder = inOrder(ipvSessionItem, ipvSessionService);
        inOrder.verify(ipvSessionItem).setVot(VOT_P2);
        inOrder.verify(ipvSessionService).updateIpvSession(ipvSessionItem);
        inOrder.verify(ipvSessionItem, never()).setVot(any());
        assertEquals(VOT_P2, ipvSessionItem.getVot());
    }

    @Test
    void shouldReturnJourneyReuseResponseIfCheckRequiresAdditionalEvidenceResponseTrue()
            throws Exception {
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(userIdentityService.getUserIssuedCredentials(TEST_USER_ID)).thenReturn(CREDENTIALS);
        when(userIdentityService.checkNameAndFamilyNameCorrelationInCredentials(TEST_USER_ID))
                .thenReturn(true);
        when(userIdentityService.checkBirthDateCorrelationInCredentials(TEST_USER_ID))
                .thenReturn(true);
        when(criResponseService.getFaceToFaceRequest(TEST_USER_ID)).thenReturn(null);
        when(gpg45ProfileEvaluator.parseCredentials(any())).thenCallRealMethod();
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(userIdentityService.checkRequiresAdditionalEvidence(TEST_USER_ID)).thenReturn(true);
        JourneyResponse journeyResponse =
                toResponseClass(
                        checkExistingIdentityHandler.handleRequest(event, context),
                        JourneyResponse.class);

        assertEquals(JOURNEY_RESET_IDENTITY, journeyResponse);

        ArgumentCaptor<AuditEvent> auditEventArgumentCaptor =
                ArgumentCaptor.forClass(AuditEvent.class);
        verify(auditService).sendAuditEvent(auditEventArgumentCaptor.capture());
        assertEquals(
                AuditEventTypes.IPV_IDENTITY_REUSE_RESET,
                auditEventArgumentCaptor.getValue().getEventName());
        verify(clientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());

        verify(ipvSessionItem, never()).setVot(any());
        assertNull(ipvSessionItem.getVot());
    }

    private VcStoreItem createVcStoreItem(String credentialIssuer, String credential) {
        Instant dateCreated = Instant.now();
        VcStoreItem vcStoreItem = new VcStoreItem();
        vcStoreItem.setUserId("user-id-1");
        vcStoreItem.setCredentialIssuer(credentialIssuer);
        vcStoreItem.setCredential(credential);
        vcStoreItem.setDateCreated(dateCreated);
        vcStoreItem.setExpirationTime(dateCreated.plusSeconds(1000L));
        return vcStoreItem;
    }

    private CriResponseItem createCriResponseStoreItem(
            String userId, String credentialIssuer, String issuerResponse, Instant dateCreated) {
        CriResponseItem criResponseItem = new CriResponseItem();
        criResponseItem.setUserId(userId);
        criResponseItem.setCredentialIssuer(credentialIssuer);
        criResponseItem.setIssuerResponse(issuerResponse);
        criResponseItem.setDateCreated(dateCreated);
        criResponseItem.setStatus(CriResponseService.STATUS_PENDING);
        return criResponseItem;
    }

    private CriResponseItem createCriErrorResponseStoreItem(
            String userId, String credentialIssuer, String issuerResponse, Instant dateCreated) {
        CriResponseItem criResponseItem = new CriResponseItem();
        criResponseItem.setUserId(userId);
        criResponseItem.setCredentialIssuer(credentialIssuer);
        criResponseItem.setIssuerResponse(issuerResponse);
        criResponseItem.setDateCreated(dateCreated);
        criResponseItem.setStatus(CriResponseService.STATUS_ERROR);
        return criResponseItem;
    }
}
