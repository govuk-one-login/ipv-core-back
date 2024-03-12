package uk.gov.di.ipv.core.checkexistingidentity;

import com.amazonaws.services.lambda.runtime.Context;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.apache.http.HttpStatus;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;
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
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.domain.cimitvc.ContraIndicator;
import uk.gov.di.ipv.core.library.domain.cimitvc.Mitigation;
import uk.gov.di.ipv.core.library.dto.ContraIndicatorMitigationDetailsDto;
import uk.gov.di.ipv.core.library.enums.Vot;
import uk.gov.di.ipv.core.library.exceptions.ConfigException;
import uk.gov.di.ipv.core.library.exceptions.CredentialParseException;
import uk.gov.di.ipv.core.library.exceptions.MitigationRouteConfigNotFoundException;
import uk.gov.di.ipv.core.library.exceptions.SqsException;
import uk.gov.di.ipv.core.library.exceptions.UnrecognisedCiException;
import uk.gov.di.ipv.core.library.gpg45.Gpg45ProfileEvaluator;
import uk.gov.di.ipv.core.library.gpg45.enums.Gpg45Profile;
import uk.gov.di.ipv.core.library.gpg45.exception.UnknownEvidenceTypeException;
import uk.gov.di.ipv.core.library.helpers.SecureTokenHelper;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.CriResponseItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.CiMitService;
import uk.gov.di.ipv.core.library.service.CiMitUtilityService;
import uk.gov.di.ipv.core.library.service.ClientOAuthSessionDetailsService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.CriResponseService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.service.UserIdentityService;
import uk.gov.di.ipv.core.library.verifiablecredential.service.VerifiableCredentialService;

import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;

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
import static uk.gov.di.ipv.core.library.config.CoreFeatureFlag.INHERITED_IDENTITY;
import static uk.gov.di.ipv.core.library.config.CoreFeatureFlag.RESET_IDENTITY;
import static uk.gov.di.ipv.core.library.domain.CriConstants.F2F_CRI;
import static uk.gov.di.ipv.core.library.domain.CriConstants.HMRC_MIGRATION_CRI;
import static uk.gov.di.ipv.core.library.domain.VocabConstants.VOT_CLAIM_NAME;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.EC_PRIVATE_KEY_JWK;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.M1A_ADDRESS_VC;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.M1A_EXPERIAN_FRAUD_VC;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.M1B_DCMAW_VC;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.PASSPORT_NON_DCMAW_SUCCESSFUL_VC;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcF2fM1a;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcHmrcMigrationPCL250NoEvidence;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcVerificationM1a;
import static uk.gov.di.ipv.core.library.journeyuris.JourneyUris.JOURNEY_ERROR_PATH;
import static uk.gov.di.ipv.core.library.journeyuris.JourneyUris.JOURNEY_F2F_FAIL_PATH;
import static uk.gov.di.ipv.core.library.journeyuris.JourneyUris.JOURNEY_FAIL_WITH_CI_AND_FORCED_RESET_PATH;
import static uk.gov.di.ipv.core.library.journeyuris.JourneyUris.JOURNEY_FAIL_WITH_CI_PATH;
import static uk.gov.di.ipv.core.library.journeyuris.JourneyUris.JOURNEY_IN_MIGRATION_REUSE_PATH;
import static uk.gov.di.ipv.core.library.journeyuris.JourneyUris.JOURNEY_IPV_GPG45_MEDIUM_PATH;
import static uk.gov.di.ipv.core.library.journeyuris.JourneyUris.JOURNEY_OPERATIONAL_PROFILE_REUSE_PATH;
import static uk.gov.di.ipv.core.library.journeyuris.JourneyUris.JOURNEY_PENDING_PATH;
import static uk.gov.di.ipv.core.library.journeyuris.JourneyUris.JOURNEY_RESET_GPG45_IDENTITY_PATH;
import static uk.gov.di.ipv.core.library.journeyuris.JourneyUris.JOURNEY_RESET_IDENTITY_PATH;
import static uk.gov.di.ipv.core.library.journeyuris.JourneyUris.JOURNEY_REUSE_PATH;

@ExtendWith(MockitoExtension.class)
class CheckExistingIdentityHandlerTest {
    private static final String TEST_SESSION_ID = "test-session-id";
    private static final String TEST_USER_ID = "test-user-id";
    private static final String TEST_JOURNEY_ID = "test-journey-id";
    private static final String TEST_CLIENT_SOURCE_IP = "test-client-source-ip";
    private static final String TEST_FEATURE_SET = "test-feature-set";
    private static final String TEST_CLIENT_OAUTH_SESSION_ID =
            SecureTokenHelper.getInstance().generate();
    private static final String TEST_JOURNEY = "journey/check-existing-identity";
    private static List<VerifiableCredential> VCS_FROM_STORE;
    private static final String TICF_CRI = "ticf";
    private static final JourneyResponse JOURNEY_REUSE = new JourneyResponse(JOURNEY_REUSE_PATH);
    private static final JourneyResponse JOURNEY_OP_PROFILE_REUSE =
            new JourneyResponse(JOURNEY_OPERATIONAL_PROFILE_REUSE_PATH);
    private static final JourneyResponse JOURNEY_IN_MIGRATION_REUSE =
            new JourneyResponse(JOURNEY_IN_MIGRATION_REUSE_PATH);
    private static final JourneyResponse JOURNEY_IPV_GPG45_MEDIUM =
            new JourneyResponse(JOURNEY_IPV_GPG45_MEDIUM_PATH);
    private static final JourneyResponse JOURNEY_RESET_IDENTITY =
            new JourneyResponse(JOURNEY_RESET_IDENTITY_PATH);
    private static final JourneyResponse JOURNEY_RESET_GPG45_IDENTITY =
            new JourneyResponse(JOURNEY_RESET_GPG45_IDENTITY_PATH);
    private static final JourneyResponse JOURNEY_PENDING =
            new JourneyResponse(JOURNEY_PENDING_PATH);
    private static final JourneyResponse JOURNEY_F2F_FAIL =
            new JourneyResponse(JOURNEY_F2F_FAIL_PATH);
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static ECDSASigner jwtSigner;
    private static VerifiableCredential pcl200Vc;
    private static VerifiableCredential pcl250Vc;
    @Mock private Context context;
    @Mock private UserIdentityService userIdentityService;
    @Mock private CriResponseService criResponseService;
    @Mock private IpvSessionService ipvSessionService;
    @Mock private Gpg45ProfileEvaluator gpg45ProfileEvaluator;
    @Mock private ConfigService configService;
    @Mock private AuditService auditService;
    @Mock private ClientOAuthSessionDetailsService clientOAuthSessionDetailsService;
    @Mock private CiMitService ciMitService;
    @Mock private CiMitUtilityService ciMitUtilityService;
    @Mock private VerifiableCredentialService mockVerifiableCredentialService;
    @InjectMocks private CheckExistingIdentityHandler checkExistingIdentityHandler;

    @Spy private IpvSessionItem ipvSessionItem;
    private JourneyRequest event;
    private ClientOAuthSessionItem clientOAuthSessionItem;

    @BeforeAll
    static void setUp() throws Exception {
        jwtSigner = createJwtSigner();
        pcl200Vc = createOperationalProfileVc(Vot.PCL200);
        pcl250Vc = createOperationalProfileVc(Vot.PCL250);
        VCS_FROM_STORE =
                List.of(
                        PASSPORT_NON_DCMAW_SUCCESSFUL_VC,
                        M1A_ADDRESS_VC,
                        M1A_EXPERIAN_FRAUD_VC,
                        vcVerificationM1a(),
                        M1B_DCMAW_VC);
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
                        .vtr(List.of(Vot.P2.name()))
                        .build();
    }

    @Test
    void shouldReturnJourneyResetIdentityIfResetIdentityFeatureFlagIsEnabled() throws Exception {
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
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

    @Nested
    @DisplayName("reuse journeys")
    class ReuseJourneys {
        @BeforeEach
        public void reuseSetup() {
            when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
            when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                    .thenReturn(clientOAuthSessionItem);
        }

        @Test
        void shouldReturnJourneyReuseResponseIfScoresSatisfyM1AGpg45Profile() throws Exception {
            when(gpg45ProfileEvaluator.getFirstMatchingProfile(
                            any(), eq(Vot.P2.getSupportedGpg45Profiles())))
                    .thenReturn(Optional.of(Gpg45Profile.M1A));
            when(userIdentityService.areVcsCorrelated(any())).thenReturn(true);

            JourneyResponse journeyResponse =
                    toResponseClass(
                            checkExistingIdentityHandler.handleRequest(event, context),
                            JourneyResponse.class);

            assertEquals(JOURNEY_REUSE, journeyResponse);

            verify(mockVerifiableCredentialService).deleteVcStoreItem(TEST_USER_ID, TICF_CRI);
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
            verify(mockVerifiableCredentialService, times(1)).getVcs(TEST_USER_ID);

            InOrder inOrder = inOrder(ipvSessionItem, ipvSessionService);
            inOrder.verify(ipvSessionItem).setVot(Vot.P2);
            inOrder.verify(ipvSessionService).updateIpvSession(ipvSessionItem);
            inOrder.verify(ipvSessionItem, never()).setVot(any());
            assertEquals(Vot.P2, ipvSessionItem.getVot());
        }

        @Test
        void shouldReturnJourneyReuseResponseIfScoresSatisfyM1BGpg45Profile() throws Exception {
            when(gpg45ProfileEvaluator.getFirstMatchingProfile(
                            any(), eq(Vot.P2.getSupportedGpg45Profiles())))
                    .thenReturn(Optional.of(Gpg45Profile.M1B));
            when(userIdentityService.areVcsCorrelated(any())).thenReturn(true);

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
            inOrder.verify(ipvSessionItem).setVot(Vot.P2);
            inOrder.verify(ipvSessionService).updateIpvSession(ipvSessionItem);
            inOrder.verify(ipvSessionItem, never()).setVot(any());
            assertEquals(Vot.P2, ipvSessionItem.getVot());
        }

        @Test // User returning after migration
        void
                shouldReturnJourneyOpProfileReuseResponseIfPCL200RequestedAndMetWhenNoVcInCurrentSession()
                        throws CredentialParseException {
            when(mockVerifiableCredentialService.getVcs(any())).thenReturn(List.of(pcl200Vc));
            clientOAuthSessionItem.setVtr(
                    List.of(Vot.P2.name(), Vot.PCL250.name(), Vot.PCL200.name()));
            ipvSessionItem.setVcReceivedThisSession(List.of());

            JourneyResponse journeyResponse =
                    toResponseClass(
                            checkExistingIdentityHandler.handleRequest(event, context),
                            JourneyResponse.class);

            assertEquals(JOURNEY_OP_PROFILE_REUSE, journeyResponse);
            InOrder inOrder = inOrder(ipvSessionItem, ipvSessionService);
            inOrder.verify(ipvSessionItem).setVot(Vot.PCL200);
            inOrder.verify(ipvSessionService).updateIpvSession(ipvSessionItem);
            inOrder.verify(ipvSessionItem, never()).setVot(any());
            assertEquals(Vot.PCL200, ipvSessionItem.getVot());
        }

        @Test // User returning after migration
        void
                shouldReturnJourneyOpProfileReuseResponseIfPCL250RequestedAndMetWhenNoVcInCurrentSession()
                        throws CredentialParseException {
            when(mockVerifiableCredentialService.getVcs(any())).thenReturn(List.of(pcl250Vc));
            clientOAuthSessionItem.setVtr(List.of(Vot.P2.name(), Vot.PCL250.name()));
            ipvSessionItem.setVcReceivedThisSession(List.of());

            JourneyResponse journeyResponse =
                    toResponseClass(
                            checkExistingIdentityHandler.handleRequest(event, context),
                            JourneyResponse.class);

            assertEquals(JOURNEY_OP_PROFILE_REUSE, journeyResponse);

            InOrder inOrder = inOrder(ipvSessionItem, ipvSessionService);
            inOrder.verify(ipvSessionItem).setVot(Vot.PCL250);
            inOrder.verify(ipvSessionService).updateIpvSession(ipvSessionItem);
            inOrder.verify(ipvSessionItem, never()).setVot(any());
            assertEquals(Vot.PCL250, ipvSessionItem.getVot());
        }

        @Test // User returning after migration
        void shouldReturnJourneyOpProfileReuseResponseIfOpProfileAndPendingF2F()
                throws CredentialParseException {
            when(criResponseService.getFaceToFaceRequest(any())).thenReturn(new CriResponseItem());
            when(mockVerifiableCredentialService.getVcs(any())).thenReturn(List.of(pcl250Vc));

            clientOAuthSessionItem.setVtr(List.of(Vot.P2.name(), Vot.PCL250.name()));
            ipvSessionItem.setVcReceivedThisSession(List.of());

            JourneyResponse journeyResponse =
                    toResponseClass(
                            checkExistingIdentityHandler.handleRequest(event, context),
                            JourneyResponse.class);

            assertEquals(JOURNEY_OP_PROFILE_REUSE, journeyResponse);

            InOrder inOrder = inOrder(ipvSessionItem, ipvSessionService);
            inOrder.verify(ipvSessionItem).setVot(Vot.PCL250);
            inOrder.verify(ipvSessionService).updateIpvSession(ipvSessionItem);
            inOrder.verify(ipvSessionItem, never()).setVot(any());
            assertEquals(Vot.PCL250, ipvSessionItem.getVot());
        }

        @Test // User in process of migration
        void
                shouldReturnJourneyInMigrationReuseResponseIfPCL200RequestedAndMetWhenVcInCurrentSession()
                        throws CredentialParseException {
            when(mockVerifiableCredentialService.getVcs(any())).thenReturn(List.of(pcl200Vc));
            when(ipvSessionItem.getVcReceivedThisSession())
                    .thenReturn(List.of(pcl250Vc.getVcString()));
            clientOAuthSessionItem.setVtr(
                    List.of(Vot.P2.name(), Vot.PCL250.name(), Vot.PCL200.name()));
            ipvSessionItem.setVcReceivedThisSession(List.of(pcl200Vc.getVcString()));

            JourneyResponse journeyResponse =
                    toResponseClass(
                            checkExistingIdentityHandler.handleRequest(event, context),
                            JourneyResponse.class);

            assertEquals(JOURNEY_IN_MIGRATION_REUSE, journeyResponse);
            InOrder inOrder = inOrder(ipvSessionItem, ipvSessionService);
            inOrder.verify(ipvSessionItem).setVot(Vot.PCL200);
            inOrder.verify(ipvSessionService).updateIpvSession(ipvSessionItem);
            inOrder.verify(ipvSessionItem, never()).setVot(any());
            assertEquals(Vot.PCL200, ipvSessionItem.getVot());
        }

        @Test // User in process of migration
        void
                shouldReturnJourneyInMigrationReuseResponseIfPCL250RequestedAndMetWhenVcInCurrentSession()
                        throws CredentialParseException {
            when(mockVerifiableCredentialService.getVcs(any())).thenReturn(List.of(pcl250Vc));
            when(ipvSessionItem.getVcReceivedThisSession())
                    .thenReturn(List.of(pcl250Vc.getVcString()));
            clientOAuthSessionItem.setVtr(List.of(Vot.P2.name(), Vot.PCL250.name()));

            JourneyResponse journeyResponse =
                    toResponseClass(
                            checkExistingIdentityHandler.handleRequest(event, context),
                            JourneyResponse.class);

            assertEquals(JOURNEY_IN_MIGRATION_REUSE, journeyResponse);
            InOrder inOrder = inOrder(ipvSessionItem, ipvSessionService);
            inOrder.verify(ipvSessionItem).setVot(Vot.PCL250);
            inOrder.verify(ipvSessionService).updateIpvSession(ipvSessionItem);
            inOrder.verify(ipvSessionItem, never()).setVot(any());
            assertEquals(Vot.PCL250, ipvSessionItem.getVot());
        }

        @Test
        void shouldMatchStrongestVotRegardlessOfVtrOrder() throws Exception {
            when(gpg45ProfileEvaluator.getFirstMatchingProfile(
                            any(), eq(Vot.P2.getSupportedGpg45Profiles())))
                    .thenReturn(Optional.of(Gpg45Profile.M1B));
            when(userIdentityService.areVcsCorrelated(any())).thenReturn(true);

            clientOAuthSessionItem.setVtr(
                    List.of(Vot.PCL250.name(), Vot.PCL200.name(), Vot.P2.name()));

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
            inOrder.verify(ipvSessionItem).setVot(Vot.P2);
            inOrder.verify(ipvSessionService).updateIpvSession(ipvSessionItem);
            inOrder.verify(ipvSessionItem, never()).setVot(any());
            assertEquals(Vot.P2, ipvSessionItem.getVot());
        }
    }

    @Test
    void shouldReturnNoMatchForF2FCompleteAndVCsDoNotCorrelate() throws Exception {
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(mockVerifiableCredentialService.getVcs(TEST_USER_ID)).thenReturn(List.of(vcF2fM1a()));
        CriResponseItem criResponseItem = createCriResponseStoreItem();
        when(criResponseService.getFaceToFaceRequest(TEST_USER_ID)).thenReturn(criResponseItem);
        when(userIdentityService.areVcsCorrelated(any())).thenReturn(false);

        clientOAuthSessionItem.setVtr(List.of(Vot.PCL250.name(), Vot.PCL200.name(), Vot.P2.name()));

        JourneyResponse journeyResponse =
                toResponseClass(
                        checkExistingIdentityHandler.handleRequest(event, context),
                        JourneyResponse.class);

        assertEquals(JOURNEY_F2F_FAIL, journeyResponse);

        ArgumentCaptor<AuditEvent> auditEventArgumentCaptor =
                ArgumentCaptor.forClass(AuditEvent.class);
        verify(auditService, times(1)).sendAuditEvent(auditEventArgumentCaptor.capture());
        assertEquals(
                AuditEventTypes.IPV_F2F_CORRELATION_FAIL,
                auditEventArgumentCaptor.getAllValues().get(0).getEventName());
        verify(clientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());

        verify(ipvSessionService, never()).updateIpvSession(any());
        verify(ipvSessionItem, never()).setVot(any());
        assertNull(ipvSessionItem.getVot());
    }

    @Test
    void shouldNoMatchStrongestVotAndAlsoVCsDoNotCorrelate() throws Exception {
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(mockVerifiableCredentialService.getVcs(TEST_USER_ID)).thenReturn(List.of(vcF2fM1a()));
        when(userIdentityService.areVcsCorrelated(any())).thenReturn(false);

        clientOAuthSessionItem.setVtr(List.of(Vot.PCL250.name(), Vot.PCL200.name(), Vot.P2.name()));

        JourneyResponse journeyResponse =
                toResponseClass(
                        checkExistingIdentityHandler.handleRequest(event, context),
                        JourneyResponse.class);

        assertEquals(JOURNEY_RESET_GPG45_IDENTITY, journeyResponse);

        ArgumentCaptor<AuditEvent> auditEventArgumentCaptor =
                ArgumentCaptor.forClass(AuditEvent.class);
        verify(auditService, times(1)).sendAuditEvent(auditEventArgumentCaptor.capture());
        assertEquals(
                AuditEventTypes.IPV_IDENTITY_REUSE_RESET,
                auditEventArgumentCaptor.getValue().getEventName());
        verify(clientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());

        verify(ipvSessionService, never()).updateIpvSession(any());
        verify(ipvSessionItem, never()).setVot(any());
        assertNull(ipvSessionItem.getVot());
    }

    @ParameterizedTest
    @MethodSource("votAndVtrCombinationsThatShouldStartIpvJourney")
    void shouldReturnJourneyIpvGpg45MediumResponseIfNoProfileAttainsVot(
            Map<String, Object> votAndVtr) {
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(criResponseService.getFaceToFaceRequest(TEST_USER_ID)).thenReturn(null);
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(configService.enabled(RESET_IDENTITY.getName())).thenReturn(false);

        clientOAuthSessionItem.setVtr((List<String>) votAndVtr.get("vtr"));

        JourneyResponse journeyResponse =
                toResponseClass(
                        checkExistingIdentityHandler.handleRequest(event, context),
                        JourneyResponse.class);

        assertEquals(JOURNEY_IPV_GPG45_MEDIUM, journeyResponse);

        verify(ipvSessionItem, never()).setVot(any());
    }

    @Test
    void shouldReturnJourneyResetIdentityResponseIfScoresDoNotSatisfyM1AGpg45Profile()
            throws Exception {
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(mockVerifiableCredentialService.getVcs(TEST_USER_ID)).thenReturn(VCS_FROM_STORE);
        when(criResponseService.getFaceToFaceRequest(TEST_USER_ID)).thenReturn(null);
        when(userIdentityService.areVcsCorrelated(any())).thenReturn(true);
        when(gpg45ProfileEvaluator.getFirstMatchingProfile(
                        any(), eq(Vot.P2.getSupportedGpg45Profiles())))
                .thenReturn(Optional.empty());
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        JourneyResponse journeyResponse =
                toResponseClass(
                        checkExistingIdentityHandler.handleRequest(event, context),
                        JourneyResponse.class);

        assertEquals(JOURNEY_RESET_GPG45_IDENTITY, journeyResponse);

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
        when(criResponseService.getFaceToFaceRequest(TEST_USER_ID)).thenReturn(null);
        when(userIdentityService.areVcsCorrelated(any())).thenReturn(true);
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        JourneyResponse journeyResponse =
                toResponseClass(
                        checkExistingIdentityHandler.handleRequest(event, context),
                        JourneyResponse.class);

        assertEquals(JOURNEY_IPV_GPG45_MEDIUM_PATH, journeyResponse.getJourney());

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
        CriResponseItem criResponseItem = createCriResponseStoreItem();
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
    void shouldReturnPendingResponseIfFaceToFaceVerificationIsPendingAndBreachingCi() {
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        CriResponseItem criResponseItem = createCriResponseStoreItem();
        when(criResponseService.getFaceToFaceRequest(TEST_USER_ID)).thenReturn(criResponseItem);
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(ciMitUtilityService.isBreachingCiThreshold(any())).thenReturn(true);

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
        CriResponseItem criResponseItem = createCriErrorResponseStoreItem(Instant.now());
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
    void shouldReturnFailResponseForFaceToFaceVerificationIfNoMatchedProfile() throws Exception {
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(mockVerifiableCredentialService.getVcs(TEST_USER_ID)).thenReturn(List.of(vcF2fM1a()));
        CriResponseItem criResponseItem = createCriResponseStoreItem();
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
    void shouldReturnFailResponseForFaceToFaceIfVCsDoNotCorrelate() throws Exception {
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(mockVerifiableCredentialService.getVcs(TEST_USER_ID)).thenReturn(List.of(vcF2fM1a()));
        CriResponseItem criResponseItem = createCriResponseStoreItem();
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
    void shouldResetIdentityIfDataDoesNotCorrelateAndNotF2F() throws CredentialParseException {
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(mockVerifiableCredentialService.getVcs(TEST_USER_ID)).thenReturn(List.of(vcF2fM1a()));
        when(criResponseService.getFaceToFaceRequest(TEST_USER_ID)).thenReturn(null);
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        JourneyResponse journeyResponse =
                toResponseClass(
                        checkExistingIdentityHandler.handleRequest(event, context),
                        JourneyResponse.class);

        assertEquals(JOURNEY_RESET_GPG45_IDENTITY, journeyResponse);

        verify(ipvSessionService, never()).updateIpvSession(any());

        verify(ipvSessionItem, never()).setVot(any());
        assertNull(ipvSessionItem.getVot());
    }

    @Test
    void shouldReturn500IfCredentialOfUnknownType() throws Exception {
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(gpg45ProfileEvaluator.buildScore(any())).thenThrow(new UnknownEvidenceTypeException());
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(userIdentityService.areVcsCorrelated(any())).thenReturn(true);

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

        verify(mockVerifiableCredentialService, times(1)).getVcs(TEST_USER_ID);
        verify(criResponseService).getFaceToFaceRequest(TEST_USER_ID);
        verify(clientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());

        verify(ipvSessionService, never()).updateIpvSession(any());

        verify(ipvSessionItem, never()).setVot(any());
        assertNull(ipvSessionItem.getVot());
    }

    @Test
    void shouldReturn500IfFailedToSendAuditEvent() throws Exception {
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(mockVerifiableCredentialService.getVcs(TEST_USER_ID)).thenReturn(List.of(vcF2fM1a()));
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
        var testJourneyResponse = "/journey/test-response";
        var testContraIndicators = ContraIndicators.builder().build();

        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(ciMitService.getContraIndicators(TEST_USER_ID, TEST_JOURNEY_ID, TEST_CLIENT_SOURCE_IP))
                .thenReturn(testContraIndicators);
        when(ciMitUtilityService.isBreachingCiThreshold(testContraIndicators)).thenReturn(true);
        when(ciMitUtilityService.getCiMitigationJourneyStep(testContraIndicators))
                .thenReturn(Optional.of(new JourneyResponse(testJourneyResponse)));

        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        JourneyResponse response =
                toResponseClass(
                        checkExistingIdentityHandler.handleRequest(event, context),
                        JourneyResponse.class);

        assertEquals(testJourneyResponse, response.getJourney());
    }

    @Test
    void shouldReturnFailWithCiJourneyResponseForCiBreach() throws Exception {
        var testContraIndicators = ContraIndicators.builder().build();

        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(ciMitService.getContraIndicators(TEST_USER_ID, TEST_JOURNEY_ID, TEST_CLIENT_SOURCE_IP))
                .thenReturn(testContraIndicators);
        when(ciMitUtilityService.isBreachingCiThreshold(testContraIndicators)).thenReturn(true);
        when(ciMitUtilityService.getCiMitigationJourneyStep(testContraIndicators))
                .thenReturn(Optional.empty());

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
        when(ciMitService.getContraIndicators(anyString(), anyString(), anyString()))
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
        when(ciMitUtilityService.isBreachingCiThreshold(any())).thenReturn(true);
        when(ciMitUtilityService.getCiMitigationJourneyStep(any()))
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
    void shouldReturn500IfFailedToGetMitigationRouteFromCimitConfig() throws Exception {
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(ciMitUtilityService.isBreachingCiThreshold(any())).thenReturn(true);
        when(ciMitUtilityService.getCiMitigationJourneyStep(any()))
                .thenThrow(
                        new MitigationRouteConfigNotFoundException(
                                "mitigation route event not found"));

        JourneyErrorResponse response =
                toResponseClass(
                        checkExistingIdentityHandler.handleRequest(event, context),
                        JourneyErrorResponse.class);

        assertEquals(HttpStatus.SC_INTERNAL_SERVER_ERROR, response.getStatusCode());
        assertEquals(ErrorResponse.MITIGATION_ROUTE_CONFIG_NOT_FOUND.getCode(), response.getCode());
        assertEquals(
                ErrorResponse.MITIGATION_ROUTE_CONFIG_NOT_FOUND.getMessage(),
                response.getMessage());
    }

    @Test
    void shouldReturn500IfUnrecognisedCiReceived() throws Exception {
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(ciMitService.getContraIndicators(TEST_USER_ID, TEST_JOURNEY_ID, TEST_CLIENT_SOURCE_IP))
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

    @Test
    void shouldReturnJourneyReuseResponseIfCheckRequiresAdditionalEvidenceResponseFalse()
            throws Exception {
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(criResponseService.getFaceToFaceRequest(TEST_USER_ID)).thenReturn(null);
        when(gpg45ProfileEvaluator.getFirstMatchingProfile(
                        any(), eq(Vot.P2.getSupportedGpg45Profiles())))
                .thenReturn(Optional.of(Gpg45Profile.M1B));
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(configService.enabled(RESET_IDENTITY.getName())).thenReturn(false);
        when(userIdentityService.checkRequiresAdditionalEvidence(any())).thenReturn(false);
        when(userIdentityService.areVcsCorrelated(any())).thenReturn(true);
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

        verify(ipvSessionService, times(1)).updateIpvSession(ipvSessionItem);

        InOrder inOrder = inOrder(ipvSessionItem, ipvSessionService);
        inOrder.verify(ipvSessionItem).setVot(Vot.P2);
        inOrder.verify(ipvSessionService).updateIpvSession(ipvSessionItem);
        inOrder.verify(ipvSessionItem, never()).setVot(any());
        assertEquals(Vot.P2, ipvSessionItem.getVot());
    }

    @Test
    void shouldReturnJourneyResetIdentityResponseIfCheckRequiresAdditionalEvidenceResponseTrue()
            throws Exception {
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(mockVerifiableCredentialService.getVcs(TEST_USER_ID)).thenReturn(VCS_FROM_STORE);
        when(criResponseService.getFaceToFaceRequest(TEST_USER_ID)).thenReturn(null);
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(userIdentityService.checkRequiresAdditionalEvidence(any())).thenReturn(true);
        when(userIdentityService.areVcsCorrelated(any())).thenReturn(true);

        JourneyResponse journeyResponse =
                toResponseClass(
                        checkExistingIdentityHandler.handleRequest(event, context),
                        JourneyResponse.class);

        assertEquals(JOURNEY_RESET_GPG45_IDENTITY, journeyResponse);

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
    void shouldRemoveOperationalProfileIfMatchingGpg45ProfileIsPresent() throws Exception {
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(mockVerifiableCredentialService.getVcs(TEST_USER_ID))
                .thenReturn(
                        Stream.concat(
                                        VCS_FROM_STORE.stream(),
                                        Stream.of(vcHmrcMigrationPCL250NoEvidence()))
                                .toList());

        when(criResponseService.getFaceToFaceRequest(TEST_USER_ID)).thenReturn(null);
        when(gpg45ProfileEvaluator.getFirstMatchingProfile(
                        any(), eq(Vot.P2.getSupportedGpg45Profiles())))
                .thenReturn(Optional.of(Gpg45Profile.M1B));
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(userIdentityService.checkRequiresAdditionalEvidence(any())).thenReturn(false);
        when(userIdentityService.areVcsCorrelated(any())).thenReturn(true);
        when(configService.enabled(anyString())).thenReturn(false).thenReturn(true);

        JourneyResponse journeyResponse =
                toResponseClass(
                        checkExistingIdentityHandler.handleRequest(event, context),
                        JourneyResponse.class);
        assertEquals(JOURNEY_REUSE, journeyResponse);
        verify(mockVerifiableCredentialService).deleteHmrcInheritedIdentityIfPresent(any());

        ArgumentCaptor<String> configServiceArgumentCaptor = ArgumentCaptor.forClass(String.class);
        verify(configService, times(2)).enabled(configServiceArgumentCaptor.capture());
        assertEquals(RESET_IDENTITY.getName(), configServiceArgumentCaptor.getAllValues().get(0));
        assertEquals(
                INHERITED_IDENTITY.getName(), configServiceArgumentCaptor.getAllValues().get(1));
    }

    @Test
    void shouldNotRemoveOperationalProfileIfMatchingGpg45ProfileIsNotPresent() throws Exception {
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(mockVerifiableCredentialService.getVcs(TEST_USER_ID))
                .thenReturn(
                        Stream.concat(
                                        VCS_FROM_STORE.stream(),
                                        Stream.of(vcHmrcMigrationPCL250NoEvidence()))
                                .toList());
        when(criResponseService.getFaceToFaceRequest(TEST_USER_ID)).thenReturn(null);
        when(gpg45ProfileEvaluator.getFirstMatchingProfile(
                        any(), eq(Vot.P2.getSupportedGpg45Profiles())))
                .thenReturn(Optional.empty());
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(userIdentityService.checkRequiresAdditionalEvidence(any())).thenReturn(false);
        when(userIdentityService.areVcsCorrelated(any())).thenReturn(true);
        //        enables the inherited identity feature (could be better)
        when(configService.enabled(anyString())).thenReturn(false).thenReturn(true);

        JourneyResponse journeyResponse =
                toResponseClass(
                        checkExistingIdentityHandler.handleRequest(event, context),
                        JourneyResponse.class);
        assertEquals(JOURNEY_RESET_GPG45_IDENTITY, journeyResponse);
        InOrder inOrder = inOrder(mockVerifiableCredentialService);
        inOrder.verify(mockVerifiableCredentialService).deleteVcStoreItem(TEST_USER_ID, TICF_CRI);
        inOrder.verify(mockVerifiableCredentialService, never())
                .deleteVcStoreItem(TEST_USER_ID, HMRC_MIGRATION_CRI);
    }

    @Test
    void
            shouldReturnJourneyFailedWithCiAndForcedResetResponseIfResetIdentityTrueCiMitigationJourneyStepPresentAndNoMitigationJourneyStep()
                    throws Exception {
        var testContraIndicators = ContraIndicators.builder().build();
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(ciMitService.getContraIndicators(TEST_USER_ID, TEST_JOURNEY_ID, TEST_CLIENT_SOURCE_IP))
                .thenReturn(testContraIndicators);
        when(configService.enabled(RESET_IDENTITY.getName())).thenReturn(true);
        when(ciMitUtilityService.isBreachingCiThreshold(any())).thenReturn(true);
        when(ciMitUtilityService.getCiMitigationJourneyStep(any())).thenReturn(Optional.empty());

        JourneyResponse journeyResponse =
                toResponseClass(
                        checkExistingIdentityHandler.handleRequest(event, context),
                        JourneyResponse.class);

        assertEquals(JOURNEY_FAIL_WITH_CI_AND_FORCED_RESET_PATH, journeyResponse.getJourney());
    }

    @Test
    void
            shouldReturnMitigationJourneyStepResponseIfResetIdentityTrueCiMitigationJourneyStepPresentAndMitigationJourneyStepPresent()
                    throws Exception {
        var testJourneyResponse = "/journey/test-response";
        var testContraIndicators = ContraIndicators.builder().build();
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(ciMitService.getContraIndicators(TEST_USER_ID, TEST_JOURNEY_ID, TEST_CLIENT_SOURCE_IP))
                .thenReturn(testContraIndicators);
        when(configService.enabled(RESET_IDENTITY.getName())).thenReturn(true);
        when(ciMitUtilityService.isBreachingCiThreshold(any())).thenReturn(true);
        when(ciMitUtilityService.getCiMitigationJourneyStep(testContraIndicators))
                .thenReturn(Optional.of(new JourneyResponse(testJourneyResponse)));

        JourneyResponse journeyResponse =
                toResponseClass(
                        checkExistingIdentityHandler.handleRequest(event, context),
                        JourneyResponse.class);

        assertEquals(testJourneyResponse, journeyResponse.getJourney());
    }

    @Test
    void shouldReturnSameMitigationJourneyWhenCiAlreadyMitigated() throws Exception {
        var code = "ci_code";
        var journey = "some_mitigation";
        var mitigatedCI =
                ContraIndicator.builder().mitigation(List.of(Mitigation.builder().build())).build();
        var testContraIndicators =
                ContraIndicators.builder().contraIndicatorsMap(Map.of(code, mitigatedCI)).build();
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(ciMitService.getContraIndicators(TEST_USER_ID, TEST_JOURNEY_ID, TEST_CLIENT_SOURCE_IP))
                .thenReturn(testContraIndicators);
        when(ciMitUtilityService.isBreachingCiThreshold(testContraIndicators)).thenReturn(false);

        when(ciMitUtilityService.hasMitigatedContraIndicator(testContraIndicators))
                .thenReturn(Optional.of(mitigatedCI));
        when(ciMitUtilityService.getMitigatedCiJourneyStep(mitigatedCI))
                .thenReturn(Optional.of(new JourneyResponse(journey)));

        JourneyResponse journeyResponse =
                toResponseClass(
                        checkExistingIdentityHandler.handleRequest(event, context),
                        JourneyResponse.class);

        assertEquals(journey, journeyResponse.getJourney());
    }

    private static Stream<Map<String, Object>> votAndVtrCombinationsThatShouldStartIpvJourney() {
        return Stream.of(
                Map.of("vtr", List.of(Vot.P2), "operationalCredVot", Optional.empty()),
                Map.of("vtr", List.of(Vot.P2), "operationalCredVot", Optional.of(Vot.PCL200)),
                Map.of("vtr", List.of(Vot.P2), "operationalCredVot", Optional.of(Vot.PCL250)),
                Map.of("vtr", List.of(Vot.P2, Vot.PCL250), "operationalCredVot", Optional.empty()),
                Map.of(
                        "vtr",
                        List.of(Vot.P2, Vot.PCL250),
                        "operationalCredVot",
                        Optional.of(Vot.PCL200)),
                Map.of(
                        "vtr",
                        List.of(Vot.P2, Vot.PCL250, Vot.PCL200),
                        "operationalCredVot",
                        Optional.empty()));
    }

    private <T> T toResponseClass(Map<String, Object> handlerOutput, Class<T> responseClass) {
        return MAPPER.convertValue(handlerOutput, responseClass);
    }

    private CriResponseItem createCriResponseStoreItem() {
        CriResponseItem criResponseItem = new CriResponseItem();
        criResponseItem.setUserId(TEST_USER_ID);
        criResponseItem.setCredentialIssuer(F2F_CRI);
        criResponseItem.setIssuerResponse(PASSPORT_NON_DCMAW_SUCCESSFUL_VC.getVcString());
        criResponseItem.setDateCreated(Instant.now());
        criResponseItem.setStatus(CriResponseService.STATUS_PENDING);
        return criResponseItem;
    }

    private CriResponseItem createCriErrorResponseStoreItem(Instant dateCreated) {
        CriResponseItem criResponseItem = new CriResponseItem();
        criResponseItem.setUserId(TEST_USER_ID);
        criResponseItem.setCredentialIssuer(F2F_CRI);
        criResponseItem.setIssuerResponse(PASSPORT_NON_DCMAW_SUCCESSFUL_VC.getVcString());
        criResponseItem.setDateCreated(dateCreated);
        criResponseItem.setStatus(CriResponseService.STATUS_ERROR);
        return criResponseItem;
    }

    private static VerifiableCredential createOperationalProfileVc(Vot vot) throws Exception {
        var jwt =
                new SignedJWT(
                        new JWSHeader(JWSAlgorithm.ES256),
                        new JWTClaimsSet.Builder().claim(VOT_CLAIM_NAME, vot.name()).build());
        jwt.sign(jwtSigner);
        return VerifiableCredential.fromValidJwt(TEST_USER_ID, HMRC_MIGRATION_CRI, jwt);
    }

    private static ECDSASigner createJwtSigner() throws Exception {
        return new ECDSASigner(ECKey.parse(EC_PRIVATE_KEY_JWK).toECPrivateKey());
    }
}
