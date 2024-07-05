package uk.gov.di.ipv.core.checkexistingidentity;

import com.amazonaws.services.lambda.runtime.Context;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.http.HTTPResponse;
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
import org.mockito.Captor;
import org.mockito.InOrder;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
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
import uk.gov.di.ipv.core.library.enums.EvcsVCState;
import uk.gov.di.ipv.core.library.enums.Vot;
import uk.gov.di.ipv.core.library.exception.EvcsServiceException;
import uk.gov.di.ipv.core.library.exceptions.ConfigException;
import uk.gov.di.ipv.core.library.exceptions.CredentialParseException;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.core.library.exceptions.UnrecognisedCiException;
import uk.gov.di.ipv.core.library.exceptions.VerifiableCredentialException;
import uk.gov.di.ipv.core.library.gpg45.Gpg45ProfileEvaluator;
import uk.gov.di.ipv.core.library.gpg45.enums.Gpg45Profile;
import uk.gov.di.ipv.core.library.helpers.SecureTokenHelper;
import uk.gov.di.ipv.core.library.helpers.TestVc;
import uk.gov.di.ipv.core.library.journeyuris.JourneyUris;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.CriResponseItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.CiMitService;
import uk.gov.di.ipv.core.library.service.CiMitUtilityService;
import uk.gov.di.ipv.core.library.service.ClientOAuthSessionDetailsService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.CriResponseService;
import uk.gov.di.ipv.core.library.service.EvcsMigrationService;
import uk.gov.di.ipv.core.library.service.EvcsService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.service.UserIdentityService;
import uk.gov.di.ipv.core.library.verifiablecredential.service.SessionCredentialsService;
import uk.gov.di.ipv.core.library.verifiablecredential.service.VerifiableCredentialService;

import java.time.Instant;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.COMPONENT_ID;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.FRAUD_CHECK_EXPIRY_PERIOD_HOURS;
import static uk.gov.di.ipv.core.library.config.CoreFeatureFlag.EVCS_READ_ENABLED;
import static uk.gov.di.ipv.core.library.config.CoreFeatureFlag.EVCS_WRITE_ENABLED;
import static uk.gov.di.ipv.core.library.config.CoreFeatureFlag.INHERITED_IDENTITY;
import static uk.gov.di.ipv.core.library.config.CoreFeatureFlag.P1_JOURNEYS_ENABLED;
import static uk.gov.di.ipv.core.library.config.CoreFeatureFlag.REPEAT_FRAUD_CHECK;
import static uk.gov.di.ipv.core.library.config.CoreFeatureFlag.RESET_IDENTITY;
import static uk.gov.di.ipv.core.library.domain.Cri.F2F;
import static uk.gov.di.ipv.core.library.domain.Cri.HMRC_MIGRATION;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_CLAIM;
import static uk.gov.di.ipv.core.library.domain.VocabConstants.VOT_CLAIM_NAME;
import static uk.gov.di.ipv.core.library.enums.EvcsVCState.PENDING_RETURN;
import static uk.gov.di.ipv.core.library.enums.Vot.P1;
import static uk.gov.di.ipv.core.library.enums.Vot.P2;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.EC_PRIVATE_KEY_JWK;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.DCMAW_EVIDENCE_VRI_CHECK;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.EXPIRED_M1A_EXPERIAN_FRAUD_VC;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.M1A_ADDRESS_VC;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.M1A_EXPERIAN_FRAUD_VC;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.M1B_DCMAW_VC;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.PASSPORT_NON_DCMAW_SUCCESSFUL_VC;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcDrivingPermit;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcF2fBrp;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcF2fIdCard;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcF2fM1a;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcHmrcMigration;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcHmrcMigrationPCL250NoEvidence;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcVerificationM1a;
import static uk.gov.di.ipv.core.library.journeyuris.JourneyUris.JOURNEY_ENHANCED_VERIFICATION_F2F_FAIL_PATH;
import static uk.gov.di.ipv.core.library.journeyuris.JourneyUris.JOURNEY_ENHANCED_VERIFICATION_PATH;
import static uk.gov.di.ipv.core.library.journeyuris.JourneyUris.JOURNEY_F2F_FAIL_PATH;
import static uk.gov.di.ipv.core.library.journeyuris.JourneyUris.JOURNEY_FAIL_WITH_CI_PATH;
import static uk.gov.di.ipv.core.library.journeyuris.JourneyUris.JOURNEY_IN_MIGRATION_REUSE_PATH;
import static uk.gov.di.ipv.core.library.journeyuris.JourneyUris.JOURNEY_IPV_GPG45_LOW_PATH;
import static uk.gov.di.ipv.core.library.journeyuris.JourneyUris.JOURNEY_IPV_GPG45_MEDIUM_PATH;
import static uk.gov.di.ipv.core.library.journeyuris.JourneyUris.JOURNEY_OPERATIONAL_PROFILE_REUSE_PATH;
import static uk.gov.di.ipv.core.library.journeyuris.JourneyUris.JOURNEY_PENDING_PATH;
import static uk.gov.di.ipv.core.library.journeyuris.JourneyUris.JOURNEY_REPEAT_FRAUD_CHECK_PATH;
import static uk.gov.di.ipv.core.library.journeyuris.JourneyUris.JOURNEY_REPROVE_IDENTITY_GPG45_LOW_PATH;
import static uk.gov.di.ipv.core.library.journeyuris.JourneyUris.JOURNEY_REPROVE_IDENTITY_GPG45_MEDIUM_PATH;
import static uk.gov.di.ipv.core.library.journeyuris.JourneyUris.JOURNEY_REUSE_PATH;
import static uk.gov.di.ipv.core.library.journeyuris.JourneyUris.JOURNEY_REUSE_WITH_STORE_PATH;

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
    private static final String JOURNEY_ERROR_PATH = "/journey/error";
    public static final String EVCS_TEST_TOKEN = "evcsTestToken";
    private static final List<VerifiableCredential> VCS_FROM_STORE =
            List.of(
                    PASSPORT_NON_DCMAW_SUCCESSFUL_VC,
                    M1A_ADDRESS_VC,
                    M1A_EXPERIAN_FRAUD_VC,
                    vcVerificationM1a(),
                    M1B_DCMAW_VC);
    private static final JourneyResponse JOURNEY_REUSE = new JourneyResponse(JOURNEY_REUSE_PATH);
    private static final JourneyResponse JOURNEY_REUSE_WITH_STORE =
            new JourneyResponse(JOURNEY_REUSE_WITH_STORE_PATH);
    private static final JourneyResponse JOURNEY_OP_PROFILE_REUSE =
            new JourneyResponse(JOURNEY_OPERATIONAL_PROFILE_REUSE_PATH);
    private static final JourneyResponse JOURNEY_IN_MIGRATION_REUSE =
            new JourneyResponse(JOURNEY_IN_MIGRATION_REUSE_PATH);
    private static final JourneyResponse JOURNEY_IPV_GPG45_LOW =
            new JourneyResponse(JOURNEY_IPV_GPG45_LOW_PATH);
    private static final JourneyResponse JOURNEY_IPV_GPG45_MEDIUM =
            new JourneyResponse(JOURNEY_IPV_GPG45_MEDIUM_PATH);
    private static final JourneyResponse JOURNEY_PENDING =
            new JourneyResponse(JOURNEY_PENDING_PATH);
    private static final JourneyResponse JOURNEY_F2F_FAIL =
            new JourneyResponse(JOURNEY_F2F_FAIL_PATH);
    private static final JourneyResponse JOURNEY_REPEAT_FRAUD_CHECK =
            new JourneyResponse(JOURNEY_REPEAT_FRAUD_CHECK_PATH);
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static ECDSASigner jwtSigner;
    private static VerifiableCredential pcl200Vc;
    private static VerifiableCredential pcl250Vc;
    private static VerifiableCredential gpg45Vc = vcDrivingPermit();
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
    @Mock private EvcsService mockEvcsService;
    @Mock private SessionCredentialsService mockSessionCredentialService;
    @Mock private EvcsMigrationService mockEvcsMigrationService;
    @InjectMocks private CheckExistingIdentityHandler checkExistingIdentityHandler;

    @Spy private IpvSessionItem ipvSessionItem;
    @Captor private ArgumentCaptor<AuditEvent> auditEventArgumentCaptor;
    private JourneyRequest event;
    private ClientOAuthSessionItem clientOAuthSessionItem;

    @BeforeAll
    static void setUp() throws Exception {
        jwtSigner = createJwtSigner();
        pcl200Vc = createOperationalProfileVc(Vot.PCL200);
        pcl250Vc = createOperationalProfileVc(Vot.PCL250);
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
                        .vtr(List.of(P2.name()))
                        .evcsAccessToken(EVCS_TEST_TOKEN)
                        .build();
    }

    @Test
    void shouldReturnJourneyNewGpg45MediumIdentityForP2Vtr() throws Exception {
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        JourneyResponse journeyResponse =
                toResponseClass(
                        checkExistingIdentityHandler.handleRequest(event, context),
                        JourneyResponse.class);

        assertEquals(JOURNEY_IPV_GPG45_MEDIUM, journeyResponse);

        verify(auditService, never()).sendAuditEvent(auditEventArgumentCaptor.capture());
    }

    @Test
    void shouldReturnJourneyNewGpg45LowIdentityForP1Vtr() throws Exception {
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        clientOAuthSessionItem.setVtr(List.of(P2.name(), P1.name()));
        when(configService.enabled(EVCS_WRITE_ENABLED)).thenReturn(false);
        when(configService.enabled(EVCS_READ_ENABLED)).thenReturn(false);
        when(configService.enabled(P1_JOURNEYS_ENABLED)).thenReturn(true);
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        JourneyResponse journeyResponse =
                toResponseClass(
                        checkExistingIdentityHandler.handleRequest(event, context),
                        JourneyResponse.class);

        assertEquals(JOURNEY_IPV_GPG45_LOW, journeyResponse);

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
        void shouldUseEvcsServiceWhenEnabled() throws Exception {
            var vc = vcHmrcMigration();
            vc.setMigrated(Instant.now());
            when(mockVerifiableCredentialService.getVcs(any())).thenReturn(List.of(vc));
            when(configService.enabled(EVCS_WRITE_ENABLED)).thenReturn(true);
            when(configService.enabled(EVCS_READ_ENABLED)).thenReturn(true);

            when(mockEvcsService.getVerifiableCredentialsByState(
                            any(), any(), any(EvcsVCState.class), any(EvcsVCState.class)))
                    .thenReturn(Map.of(EvcsVCState.CURRENT, List.of(gpg45Vc)));

            checkExistingIdentityHandler.handleRequest(event, context);

            verify(clientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());
            verify(mockEvcsService, times(1))
                    .getVerifiableCredentialsByState(
                            TEST_USER_ID,
                            EVCS_TEST_TOKEN,
                            EvcsVCState.CURRENT,
                            EvcsVCState.PENDING_RETURN);
        }

        @Test
        void shouldUseVcServiceWhenEvcsServiceEnabledAndReturnsEmpty() throws Exception {
            when(configService.enabled(EVCS_WRITE_ENABLED)).thenReturn(true);
            when(mockEvcsService.getVerifiableCredentialsByState(
                            any(), any(), any(EvcsVCState.class), any(EvcsVCState.class)))
                    .thenReturn(new HashMap<EvcsVCState, List<VerifiableCredential>>());

            checkExistingIdentityHandler.handleRequest(event, context);

            verify(clientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());
            verify(mockEvcsService, times(1))
                    .getVerifiableCredentialsByState(
                            TEST_USER_ID,
                            EVCS_TEST_TOKEN,
                            EvcsVCState.CURRENT,
                            EvcsVCState.PENDING_RETURN);
            verify(mockVerifiableCredentialService, times(1)).getVcs(TEST_USER_ID);
        }

        @Test
        void shouldReturnJourneyReuseResponseIfScoresSatisfyM1AGpg45Profile_alsoStoreVcsInEvcs()
                throws Exception {
            Mockito.lenient().when(configService.enabled(EVCS_WRITE_ENABLED)).thenReturn(true);
            VerifiableCredential hmrcMigrationVC = vcHmrcMigration();

            when(mockVerifiableCredentialService.getVcs(any()))
                    .thenReturn(List.of(gpg45Vc, hmrcMigrationVC));
            when(gpg45ProfileEvaluator.getFirstMatchingProfile(
                            any(), eq(P2.getSupportedGpg45Profiles())))
                    .thenReturn(Optional.of(Gpg45Profile.M1A));
            when(userIdentityService.areVcsCorrelated(any())).thenReturn(true);

            JourneyResponse journeyResponse =
                    toResponseClass(
                            checkExistingIdentityHandler.handleRequest(event, context),
                            JourneyResponse.class);

            assertEquals(JOURNEY_REUSE, journeyResponse);

            verify(auditService, times(3)).sendAuditEvent(auditEventArgumentCaptor.capture());
            assertEquals(
                    AuditEventTypes.IPV_GPG45_PROFILE_MATCHED,
                    auditEventArgumentCaptor.getAllValues().get(0).getEventName());
            assertEquals(
                    AuditEventTypes.IPV_IDENTITY_REUSE_COMPLETE,
                    auditEventArgumentCaptor.getAllValues().get(1).getEventName());
            assertEquals(
                    AuditEventTypes.IPV_VCS_MIGRATED,
                    auditEventArgumentCaptor.getAllValues().get(2).getEventName());
            verify(clientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());
            verify(mockVerifiableCredentialService, times(1)).getVcs(TEST_USER_ID);

            verify(mockSessionCredentialService)
                    .persistCredentials(List.of(gpg45Vc), ipvSessionItem.getIpvSessionId(), false);

            InOrder inOrder = inOrder(ipvSessionItem, ipvSessionService);
            inOrder.verify(ipvSessionItem).setVot(P2);
            inOrder.verify(ipvSessionService).updateIpvSession(ipvSessionItem);
            inOrder.verify(ipvSessionItem, never()).setVot(any());
            assertEquals(P2, ipvSessionItem.getVot());
            verify(mockEvcsMigrationService)
                    .migrateExistingIdentity(TEST_USER_ID, List.of(gpg45Vc, hmrcMigrationVC));
        }

        @Test
        void shouldReturnJourneyReuseUpdateResponseIfVcIsF2fAndHasPendingReturnInEvcs()
                throws CredentialParseException, EvcsServiceException,
                        HttpResponseExceptionWithErrorBody, VerifiableCredentialException {
            when(configService.enabled(EVCS_WRITE_ENABLED)).thenReturn(true);
            when(configService.enabled(EVCS_READ_ENABLED)).thenReturn(true);
            var vcs = List.of(gpg45Vc, vcF2fM1a());
            when(mockVerifiableCredentialService.getVcs(any())).thenReturn(vcs);
            when(mockEvcsService.getVerifiableCredentialsByState(
                            any(), any(), any(EvcsVCState.class), any(EvcsVCState.class)))
                    .thenReturn(Map.of(PENDING_RETURN, vcs));

            when(criResponseService.getFaceToFaceRequest(any())).thenReturn(new CriResponseItem());
            when(gpg45ProfileEvaluator.getFirstMatchingProfile(
                            any(), eq(P2.getSupportedGpg45Profiles())))
                    .thenReturn(Optional.of(Gpg45Profile.M1A));
            when(userIdentityService.areVcsCorrelated(any())).thenReturn(true);

            JourneyResponse journeyResponse =
                    toResponseClass(
                            checkExistingIdentityHandler.handleRequest(event, context),
                            JourneyResponse.class);

            assertEquals(JOURNEY_REUSE_WITH_STORE, journeyResponse);
            // pending vcs should not be migrated
            verify(mockEvcsMigrationService, never()).migrateExistingIdentity(any(), any());
        }

        @Test
        void shouldReturnJourneyReuseStoreResponseIfVcIsF2fAndHasPartiallyMigratedVcs()
                throws CredentialParseException, EvcsServiceException,
                        HttpResponseExceptionWithErrorBody, VerifiableCredentialException {
            when(configService.enabled(EVCS_WRITE_ENABLED)).thenReturn(true);
            when(configService.enabled(EVCS_READ_ENABLED)).thenReturn(true);
            var f2fVc1 = vcF2fM1a();
            f2fVc1.setMigrated(Instant.now());
            var f2fVc2 = vcF2fBrp();
            f2fVc2.setMigrated(Instant.now());
            var f2fVc3 = vcF2fIdCard();
            when(mockVerifiableCredentialService.getVcs(any()))
                    .thenReturn(List.of(f2fVc1, f2fVc2, f2fVc3));
            when(mockEvcsService.getVerifiableCredentialsByState(
                            any(), any(), any(EvcsVCState.class), any(EvcsVCState.class)))
                    .thenReturn(Map.of(PENDING_RETURN, List.of(f2fVc1, f2fVc2)));

            when(criResponseService.getFaceToFaceRequest(any())).thenReturn(new CriResponseItem());
            when(gpg45ProfileEvaluator.getFirstMatchingProfile(
                            any(), eq(P2.getSupportedGpg45Profiles())))
                    .thenReturn(Optional.of(Gpg45Profile.M1A));
            when(userIdentityService.areVcsCorrelated(any())).thenReturn(true);

            JourneyResponse journeyResponse =
                    toResponseClass(
                            checkExistingIdentityHandler.handleRequest(event, context),
                            JourneyResponse.class);

            assertEquals(JOURNEY_REUSE_WITH_STORE, journeyResponse);
            // pending vcs should not be migrated
            verify(mockEvcsMigrationService, never()).migrateExistingIdentity(any(), any());
        }

        @Test
        void shouldReturnJourneyReuseResponseIfScoresSatisfyM1BGpg45Profile() throws Exception {
            when(gpg45ProfileEvaluator.getFirstMatchingProfile(
                            any(), eq(P2.getSupportedGpg45Profiles())))
                    .thenReturn(Optional.of(Gpg45Profile.M1B));
            when(userIdentityService.areVcsCorrelated(any())).thenReturn(true);

            JourneyResponse journeyResponse =
                    toResponseClass(
                            checkExistingIdentityHandler.handleRequest(event, context),
                            JourneyResponse.class);

            assertEquals(JOURNEY_REUSE, journeyResponse);

            verify(auditService, times(2)).sendAuditEvent(auditEventArgumentCaptor.capture());
            assertEquals(
                    AuditEventTypes.IPV_IDENTITY_REUSE_COMPLETE,
                    auditEventArgumentCaptor.getValue().getEventName());
            verify(clientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());

            verify(ipvSessionService, times(1)).updateIpvSession(ipvSessionItem);

            InOrder inOrder = inOrder(ipvSessionItem, ipvSessionService);
            inOrder.verify(ipvSessionItem).setVot(P2);
            inOrder.verify(ipvSessionService).updateIpvSession(ipvSessionItem);
            inOrder.verify(ipvSessionItem, never()).setVot(any());
            assertEquals(P2, ipvSessionItem.getVot());
        }

        @Test // User returning after migration
        void shouldReturnJourneyOpProfileReuseResponseIfPCL200RequestedAndMetWhenNotInMigration()
                throws Exception {
            when(mockVerifiableCredentialService.getVcs(any()))
                    .thenReturn(List.of(gpg45Vc, pcl200Vc));
            clientOAuthSessionItem.setVtr(List.of(P2.name(), Vot.PCL250.name(), Vot.PCL200.name()));
            ipvSessionItem.setInheritedIdentityReceivedThisSession(false);

            JourneyResponse journeyResponse =
                    toResponseClass(
                            checkExistingIdentityHandler.handleRequest(event, context),
                            JourneyResponse.class);

            assertEquals(JOURNEY_OP_PROFILE_REUSE, journeyResponse);

            verify(mockSessionCredentialService)
                    .persistCredentials(List.of(pcl200Vc), ipvSessionItem.getIpvSessionId(), false);

            InOrder inOrder = inOrder(ipvSessionItem, ipvSessionService);
            inOrder.verify(ipvSessionItem).setVot(Vot.PCL200);
            inOrder.verify(ipvSessionService).updateIpvSession(ipvSessionItem);
            inOrder.verify(ipvSessionItem, never()).setVot(any());
            assertEquals(Vot.PCL200, ipvSessionItem.getVot());
        }

        @Test // User returning after migration
        void shouldReturnJourneyOpProfileReuseResponseIfPCL250RequestedAndMetWhenNotInMigration()
                throws Exception {
            when(mockVerifiableCredentialService.getVcs(any()))
                    .thenReturn(List.of(gpg45Vc, pcl250Vc));
            clientOAuthSessionItem.setVtr(List.of(P2.name(), Vot.PCL250.name()));
            ipvSessionItem.setInheritedIdentityReceivedThisSession(false);

            JourneyResponse journeyResponse =
                    toResponseClass(
                            checkExistingIdentityHandler.handleRequest(event, context),
                            JourneyResponse.class);

            assertEquals(JOURNEY_OP_PROFILE_REUSE, journeyResponse);

            verify(mockSessionCredentialService)
                    .persistCredentials(List.of(pcl250Vc), ipvSessionItem.getIpvSessionId(), false);

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

            clientOAuthSessionItem.setVtr(List.of(P2.name(), Vot.PCL250.name()));
            ipvSessionItem.setInheritedIdentityReceivedThisSession(false);

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
        void shouldReturnJourneyInMigrationReuseResponseIfPCL200RequestedAndMet() throws Exception {
            when(mockVerifiableCredentialService.getVcs(any()))
                    .thenReturn(List.of(gpg45Vc, pcl200Vc));
            ipvSessionItem.setInheritedIdentityReceivedThisSession(true);
            clientOAuthSessionItem.setVtr(List.of(P2.name(), Vot.PCL250.name(), Vot.PCL200.name()));

            JourneyResponse journeyResponse =
                    toResponseClass(
                            checkExistingIdentityHandler.handleRequest(event, context),
                            JourneyResponse.class);

            assertEquals(JOURNEY_IN_MIGRATION_REUSE, journeyResponse);

            verify(mockSessionCredentialService)
                    .persistCredentials(List.of(pcl200Vc), ipvSessionItem.getIpvSessionId(), true);

            InOrder inOrder = inOrder(ipvSessionItem, ipvSessionService);
            inOrder.verify(ipvSessionItem).setVot(Vot.PCL200);
            inOrder.verify(ipvSessionService).updateIpvSession(ipvSessionItem);
            inOrder.verify(ipvSessionItem, never()).setVot(any());
            assertEquals(Vot.PCL200, ipvSessionItem.getVot());
        }

        @Test // User in process of migration
        void shouldReturnJourneyInMigrationReuseResponseIfPCL250RequestedAndMet() throws Exception {
            when(mockVerifiableCredentialService.getVcs(any()))
                    .thenReturn(List.of(gpg45Vc, pcl250Vc));
            when(userIdentityService.areVcsCorrelated(any())).thenReturn(true);
            clientOAuthSessionItem.setVtr(List.of(P2.name(), Vot.PCL250.name()));
            ipvSessionItem.setInheritedIdentityReceivedThisSession(true);

            JourneyResponse journeyResponse =
                    toResponseClass(
                            checkExistingIdentityHandler.handleRequest(event, context),
                            JourneyResponse.class);

            assertEquals(JOURNEY_IN_MIGRATION_REUSE, journeyResponse);

            verify(mockSessionCredentialService)
                    .persistCredentials(List.of(pcl250Vc), ipvSessionItem.getIpvSessionId(), true);
            verify(gpg45ProfileEvaluator).buildScore(List.of(gpg45Vc));

            InOrder inOrder = inOrder(ipvSessionItem, ipvSessionService);
            inOrder.verify(ipvSessionItem).setVot(Vot.PCL250);
            inOrder.verify(ipvSessionService).updateIpvSession(ipvSessionItem);
            inOrder.verify(ipvSessionItem, never()).setVot(any());
            assertEquals(Vot.PCL250, ipvSessionItem.getVot());
        }

        @Test
        void shouldMatchStrongestVotRegardlessOfVtrOrder() throws Exception {
            when(gpg45ProfileEvaluator.getFirstMatchingProfile(
                            any(), eq(P2.getSupportedGpg45Profiles())))
                    .thenReturn(Optional.of(Gpg45Profile.M1B));
            when(userIdentityService.areVcsCorrelated(any())).thenReturn(true);

            clientOAuthSessionItem.setVtr(List.of(Vot.PCL250.name(), Vot.PCL200.name(), P2.name()));

            JourneyResponse journeyResponse =
                    toResponseClass(
                            checkExistingIdentityHandler.handleRequest(event, context),
                            JourneyResponse.class);

            assertEquals(JOURNEY_REUSE, journeyResponse);

            verify(auditService, times(2)).sendAuditEvent(auditEventArgumentCaptor.capture());
            assertEquals(
                    AuditEventTypes.IPV_IDENTITY_REUSE_COMPLETE,
                    auditEventArgumentCaptor.getValue().getEventName());
            verify(clientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());

            verify(ipvSessionService, times(1)).updateIpvSession(ipvSessionItem);

            InOrder inOrder = inOrder(ipvSessionItem, ipvSessionService);
            inOrder.verify(ipvSessionItem).setVot(P2);
            inOrder.verify(ipvSessionService).updateIpvSession(ipvSessionItem);
            inOrder.verify(ipvSessionItem, never()).setVot(any());
            assertEquals(P2, ipvSessionItem.getVot());
        }

        @Test
        void shouldReturnErrorResponseIfVcCanNotBeStoredInSessionCredentialTable()
                throws Exception {
            when(gpg45ProfileEvaluator.getFirstMatchingProfile(
                            any(), eq(P2.getSupportedGpg45Profiles())))
                    .thenReturn(Optional.of(Gpg45Profile.M1A));
            when(userIdentityService.areVcsCorrelated(any())).thenReturn(true);
            doThrow(
                            new VerifiableCredentialException(
                                    HTTPResponse.SC_SERVER_ERROR,
                                    ErrorResponse.FAILED_TO_SAVE_CREDENTIAL))
                    .when(mockSessionCredentialService)
                    .persistCredentials(any(), any(), anyBoolean());

            var journeyResponse =
                    toResponseClass(
                            checkExistingIdentityHandler.handleRequest(event, context),
                            JourneyErrorResponse.class);

            assertEquals(JOURNEY_ERROR_PATH, journeyResponse.getJourney());

            assertEquals(HTTPResponse.SC_SERVER_ERROR, journeyResponse.getStatusCode());
            assertEquals(
                    ErrorResponse.FAILED_TO_SAVE_CREDENTIAL.getCode(), journeyResponse.getCode());
            assertEquals(
                    ErrorResponse.FAILED_TO_SAVE_CREDENTIAL.getMessage(),
                    journeyResponse.getMessage());
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

        clientOAuthSessionItem.setVtr(List.of(Vot.PCL250.name(), Vot.PCL200.name(), P2.name()));

        JourneyResponse journeyResponse =
                toResponseClass(
                        checkExistingIdentityHandler.handleRequest(event, context),
                        JourneyResponse.class);

        assertEquals(JOURNEY_F2F_FAIL, journeyResponse);

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

        clientOAuthSessionItem.setVtr(List.of(Vot.PCL250.name(), Vot.PCL200.name(), P2.name()));

        JourneyResponse journeyResponse =
                toResponseClass(
                        checkExistingIdentityHandler.handleRequest(event, context),
                        JourneyResponse.class);

        assertEquals(JOURNEY_IPV_GPG45_MEDIUM, journeyResponse);

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
        clientOAuthSessionItem.setVtr((List<String>) votAndVtr.get("vtr"));

        JourneyResponse journeyResponse =
                toResponseClass(
                        checkExistingIdentityHandler.handleRequest(event, context),
                        JourneyResponse.class);

        assertEquals(JOURNEY_IPV_GPG45_MEDIUM, journeyResponse);

        verify(ipvSessionItem, never()).setVot(any());
    }

    @Test
    void shouldReturnJourneyIpvGpg45MediumResponseIfScoresDoNotSatisfyM1AGpg45Profile()
            throws Exception {
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(mockVerifiableCredentialService.getVcs(TEST_USER_ID)).thenReturn(VCS_FROM_STORE);
        when(criResponseService.getFaceToFaceRequest(TEST_USER_ID)).thenReturn(null);
        when(userIdentityService.areVcsCorrelated(any())).thenReturn(true);
        when(gpg45ProfileEvaluator.getFirstMatchingProfile(
                        any(), eq(P2.getSupportedGpg45Profiles())))
                .thenReturn(Optional.empty());
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        JourneyResponse journeyResponse =
                toResponseClass(
                        checkExistingIdentityHandler.handleRequest(event, context),
                        JourneyResponse.class);

        assertEquals(JOURNEY_IPV_GPG45_MEDIUM, journeyResponse);

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

        assertEquals(JOURNEY_ERROR_PATH, journeyResponse.getJourney());

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
    void shouldReturnJourneyIpvGpg45MediumIfDataDoesNotCorrelateAndNotF2F()
            throws CredentialParseException {
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(mockVerifiableCredentialService.getVcs(TEST_USER_ID)).thenReturn(List.of(vcF2fM1a()));
        when(criResponseService.getFaceToFaceRequest(TEST_USER_ID)).thenReturn(null);
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        JourneyResponse journeyResponse =
                toResponseClass(
                        checkExistingIdentityHandler.handleRequest(event, context),
                        JourneyResponse.class);

        assertEquals(JOURNEY_IPV_GPG45_MEDIUM, journeyResponse);

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
        when(ciMitUtilityService.getCiMitigationJourneyResponse(testContraIndicators))
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
        when(ciMitUtilityService.getCiMitigationJourneyResponse(testContraIndicators))
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
        when(ciMitUtilityService.getCiMitigationJourneyResponse(any()))
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
        when(ciMitService.getContraIndicators(TEST_USER_ID, TEST_JOURNEY_ID, TEST_CLIENT_SOURCE_IP))
                .thenThrow(new UnrecognisedCiException("Unrecognised CI"));

        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        JourneyErrorResponse response =
                toResponseClass(
                        checkExistingIdentityHandler.handleRequest(event, context),
                        JourneyErrorResponse.class);

        assertEquals(JourneyUris.JOURNEY_ERROR_PATH, response.getJourney());
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
                        any(), eq(P2.getSupportedGpg45Profiles())))
                .thenReturn(Optional.of(Gpg45Profile.M1B));
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(userIdentityService.checkRequiresAdditionalEvidence(any())).thenReturn(false);
        when(userIdentityService.areVcsCorrelated(any())).thenReturn(true);
        JourneyResponse journeyResponse =
                toResponseClass(
                        checkExistingIdentityHandler.handleRequest(event, context),
                        JourneyResponse.class);

        assertEquals(JOURNEY_REUSE, journeyResponse);

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
        inOrder.verify(ipvSessionItem).setVot(P2);
        inOrder.verify(ipvSessionService).updateIpvSession(ipvSessionItem);
        inOrder.verify(ipvSessionItem, never()).setVot(any());
        assertEquals(P2, ipvSessionItem.getVot());
        verify(mockEvcsMigrationService, times(0)).migrateExistingIdentity(any(), any());
    }

    @Test
    void shouldReturnJourneyIpvGpg45MediumResponseIfCheckRequiresAdditionalEvidenceResponseTrue()
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

        assertEquals(JOURNEY_IPV_GPG45_MEDIUM, journeyResponse);

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
                        any(), eq(P2.getSupportedGpg45Profiles())))
                .thenReturn(Optional.of(Gpg45Profile.M1B));
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(userIdentityService.checkRequiresAdditionalEvidence(any())).thenReturn(false);
        when(userIdentityService.areVcsCorrelated(any())).thenReturn(true);
        when(configService.enabled(EVCS_WRITE_ENABLED)).thenReturn(false);
        when(configService.enabled(EVCS_READ_ENABLED)).thenReturn(false);
        when(configService.enabled(RESET_IDENTITY)).thenReturn(false);
        when(configService.enabled(INHERITED_IDENTITY)).thenReturn(true);
        when(configService.enabled(REPEAT_FRAUD_CHECK)).thenReturn(false);
        when(configService.enabled(P1_JOURNEYS_ENABLED)).thenReturn(false);

        JourneyResponse journeyResponse =
                toResponseClass(
                        checkExistingIdentityHandler.handleRequest(event, context),
                        JourneyResponse.class);
        assertEquals(JOURNEY_REUSE, journeyResponse);
        verify(mockVerifiableCredentialService).deleteHmrcInheritedIdentityIfPresent(any());
    }

    @Test
    void
            shouldReturnJourneyFailedWithCiIfTrueCiMitigationJourneyStepPresentAndNoMitigationJourneyStep()
                    throws Exception {
        var testContraIndicators = ContraIndicators.builder().build();
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(ciMitService.getContraIndicators(TEST_USER_ID, TEST_JOURNEY_ID, TEST_CLIENT_SOURCE_IP))
                .thenReturn(testContraIndicators);
        when(ciMitUtilityService.isBreachingCiThreshold(any())).thenReturn(true);
        when(ciMitUtilityService.getCiMitigationJourneyResponse(any()))
                .thenReturn(Optional.empty());

        JourneyResponse journeyResponse =
                toResponseClass(
                        checkExistingIdentityHandler.handleRequest(event, context),
                        JourneyResponse.class);

        assertEquals(JOURNEY_FAIL_WITH_CI_PATH, journeyResponse.getJourney());
    }

    @Test
    void shouldReturnReproveP2JourneyStepResponseIfResetIdentityTrue() throws Exception {
        var testContraIndicators = ContraIndicators.builder().build();
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(ciMitService.getContraIndicators(TEST_USER_ID, TEST_JOURNEY_ID, TEST_CLIENT_SOURCE_IP))
                .thenReturn(testContraIndicators);
        when(configService.enabled(EVCS_WRITE_ENABLED)).thenReturn(false);
        when(configService.enabled(EVCS_READ_ENABLED)).thenReturn(false);
        when(configService.enabled(RESET_IDENTITY)).thenReturn(true);
        when(configService.enabled(P1_JOURNEYS_ENABLED)).thenReturn(false);

        JourneyResponse journeyResponse =
                toResponseClass(
                        checkExistingIdentityHandler.handleRequest(event, context),
                        JourneyResponse.class);

        assertEquals(JOURNEY_REPROVE_IDENTITY_GPG45_MEDIUM_PATH, journeyResponse.getJourney());
    }

    @Test
    void shouldReturnReproveP1JourneyStepResponseIfResetIdentityTrueAndP1InVtr() throws Exception {
        var testContraIndicators = ContraIndicators.builder().build();
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        clientOAuthSessionItem.setVtr(List.of(P2.name(), P1.name()));
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(ciMitService.getContraIndicators(TEST_USER_ID, TEST_JOURNEY_ID, TEST_CLIENT_SOURCE_IP))
                .thenReturn(testContraIndicators);
        when(configService.enabled(EVCS_WRITE_ENABLED)).thenReturn(false);
        when(configService.enabled(EVCS_READ_ENABLED)).thenReturn(false);
        when(configService.enabled(RESET_IDENTITY)).thenReturn(true);
        when(configService.enabled(P1_JOURNEYS_ENABLED)).thenReturn(true);

        JourneyResponse journeyResponse =
                toResponseClass(
                        checkExistingIdentityHandler.handleRequest(event, context),
                        JourneyResponse.class);

        assertEquals(JOURNEY_REPROVE_IDENTITY_GPG45_LOW_PATH, journeyResponse.getJourney());
    }

    @Test
    void shouldReturnSameMitigationJourneyWhenCiAlreadyMitigated() throws Exception {
        var journey = "some_mitigation";
        var mitigatedCI =
                ContraIndicator.builder().mitigation(List.of(Mitigation.builder().build())).build();
        var testContraIndicators =
                ContraIndicators.builder().usersContraIndicators(List.of(mitigatedCI)).build();
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(ciMitService.getContraIndicators(TEST_USER_ID, TEST_JOURNEY_ID, TEST_CLIENT_SOURCE_IP))
                .thenReturn(testContraIndicators);
        when(ciMitUtilityService.isBreachingCiThreshold(testContraIndicators)).thenReturn(false);

        when(ciMitUtilityService.hasMitigatedContraIndicator(testContraIndicators))
                .thenReturn(Optional.of(mitigatedCI));
        when(ciMitUtilityService.getMitigatedCiJourneyResponse(mitigatedCI))
                .thenReturn(Optional.of(new JourneyResponse(journey)));

        JourneyResponse journeyResponse =
                toResponseClass(
                        checkExistingIdentityHandler.handleRequest(event, context),
                        JourneyResponse.class);

        assertEquals(journey, journeyResponse.getJourney());
    }

    @Test
    void shouldReturnSameJourneyMitigationWhenCiAlreadyMitigatedF2F() throws Exception {
        var mitigatedCI =
                ContraIndicator.builder().mitigation(List.of(Mitigation.builder().build())).build();
        var testContraIndicators =
                ContraIndicators.builder().usersContraIndicators(List.of(mitigatedCI)).build();
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(mockVerifiableCredentialService.getVcs(TEST_USER_ID)).thenReturn(List.of(vcF2fM1a()));
        CriResponseItem criResponseItem = createCriResponseStoreItem();
        when(criResponseService.getFaceToFaceRequest(TEST_USER_ID)).thenReturn(criResponseItem);
        when(ciMitService.getContraIndicators(TEST_USER_ID, TEST_JOURNEY_ID, TEST_CLIENT_SOURCE_IP))
                .thenReturn(testContraIndicators);
        when(ciMitUtilityService.isBreachingCiThreshold(testContraIndicators)).thenReturn(false);

        when(ciMitUtilityService.hasMitigatedContraIndicator(testContraIndicators))
                .thenReturn(Optional.of(mitigatedCI));
        when(ciMitUtilityService.getMitigatedCiJourneyResponse(mitigatedCI))
                .thenReturn(Optional.of(new JourneyResponse(JOURNEY_ENHANCED_VERIFICATION_PATH)));

        JourneyResponse journeyResponse =
                toResponseClass(
                        checkExistingIdentityHandler.handleRequest(event, context),
                        JourneyResponse.class);

        assertEquals(JOURNEY_ENHANCED_VERIFICATION_F2F_FAIL_PATH, journeyResponse.getJourney());
    }

    @Test
    void
            shouldReturnErrorResponseIfNoMitigationRouteFoundForAlreadyMitigatedCiWhenBuildingF2FNoMatchResponse()
                    throws Exception {
        var mitigatedCI =
                ContraIndicator.builder().mitigation(List.of(Mitigation.builder().build())).build();
        var testContraIndicators =
                ContraIndicators.builder().usersContraIndicators(List.of(mitigatedCI)).build();
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(mockVerifiableCredentialService.getVcs(TEST_USER_ID)).thenReturn(List.of(vcF2fM1a()));
        CriResponseItem criResponseItem = createCriResponseStoreItem();
        when(criResponseService.getFaceToFaceRequest(TEST_USER_ID)).thenReturn(criResponseItem);
        when(ciMitService.getContraIndicators(TEST_USER_ID, TEST_JOURNEY_ID, TEST_CLIENT_SOURCE_IP))
                .thenReturn(testContraIndicators);
        when(ciMitUtilityService.isBreachingCiThreshold(testContraIndicators)).thenReturn(false);

        when(ciMitUtilityService.hasMitigatedContraIndicator(testContraIndicators))
                .thenReturn(Optional.of(mitigatedCI));
        when(ciMitUtilityService.getMitigatedCiJourneyResponse(mitigatedCI))
                .thenReturn(Optional.empty());

        JourneyErrorResponse response =
                toResponseClass(
                        checkExistingIdentityHandler.handleRequest(event, context),
                        JourneyErrorResponse.class);

        assertEquals(HttpStatus.SC_INTERNAL_SERVER_ERROR, response.getStatusCode());
        assertEquals(ErrorResponse.FAILED_TO_FIND_MITIGATION_ROUTE.getCode(), response.getCode());
        assertEquals(
                ErrorResponse.FAILED_TO_FIND_MITIGATION_ROUTE.getMessage(), response.getMessage());
    }

    @Test
    void shouldReturnErrorResponseWhenCiMitigationJourneyStepPresentButNotSupported()
            throws Exception {
        var journey = "unsupported_mitigation";
        var mitigatedCI =
                ContraIndicator.builder().mitigation(List.of(Mitigation.builder().build())).build();
        var testContraIndicators =
                ContraIndicators.builder().usersContraIndicators(List.of(mitigatedCI)).build();
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(mockVerifiableCredentialService.getVcs(TEST_USER_ID)).thenReturn(List.of(vcF2fM1a()));
        CriResponseItem criResponseItem = createCriResponseStoreItem();
        when(criResponseService.getFaceToFaceRequest(TEST_USER_ID)).thenReturn(criResponseItem);
        when(ciMitService.getContraIndicators(TEST_USER_ID, TEST_JOURNEY_ID, TEST_CLIENT_SOURCE_IP))
                .thenReturn(testContraIndicators);
        when(ciMitUtilityService.isBreachingCiThreshold(testContraIndicators)).thenReturn(false);

        when(ciMitUtilityService.hasMitigatedContraIndicator(testContraIndicators))
                .thenReturn(Optional.of(mitigatedCI));
        when(ciMitUtilityService.getMitigatedCiJourneyResponse(mitigatedCI))
                .thenReturn(Optional.of(new JourneyResponse(journey)));

        JourneyErrorResponse response =
                toResponseClass(
                        checkExistingIdentityHandler.handleRequest(event, context),
                        JourneyErrorResponse.class);

        assertEquals(HttpStatus.SC_INTERNAL_SERVER_ERROR, response.getStatusCode());
        assertEquals(ErrorResponse.FAILED_TO_FIND_MITIGATION_ROUTE.getCode(), response.getCode());
        assertEquals(
                ErrorResponse.FAILED_TO_FIND_MITIGATION_ROUTE.getMessage(), response.getMessage());
    }

    @Test
    void shouldReturnJourneyRepeatFraudCheckResponseIfExpiredFraudAndFlagIsTrue() throws Exception {
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        var vcs =
                List.of(
                        PASSPORT_NON_DCMAW_SUCCESSFUL_VC,
                        M1A_ADDRESS_VC,
                        EXPIRED_M1A_EXPERIAN_FRAUD_VC,
                        vcVerificationM1a(),
                        M1B_DCMAW_VC);
        when(mockVerifiableCredentialService.getVcs(TEST_USER_ID)).thenReturn(vcs);

        when(gpg45ProfileEvaluator.getFirstMatchingProfile(
                        any(), eq(P2.getSupportedGpg45Profiles())))
                .thenReturn(Optional.of(Gpg45Profile.M1B));
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(userIdentityService.checkRequiresAdditionalEvidence(any())).thenReturn(false);
        when(userIdentityService.areVcsCorrelated(any())).thenReturn(true);
        when(configService.enabled(EVCS_WRITE_ENABLED)).thenReturn(false);
        when(configService.enabled(EVCS_READ_ENABLED)).thenReturn(false);
        when(configService.enabled(RESET_IDENTITY)).thenReturn(false);
        when(configService.enabled(INHERITED_IDENTITY)).thenReturn(false);
        when(configService.enabled(REPEAT_FRAUD_CHECK)).thenReturn(true);
        when(configService.enabled(P1_JOURNEYS_ENABLED)).thenReturn(false);
        when(configService.getSsmParameter(COMPONENT_ID)).thenReturn("http://ipv/");
        when(configService.getSsmParameter(FRAUD_CHECK_EXPIRY_PERIOD_HOURS)).thenReturn("1");

        JourneyResponse journeyResponse =
                toResponseClass(
                        checkExistingIdentityHandler.handleRequest(event, context),
                        JourneyResponse.class);
        assertEquals(JOURNEY_REPEAT_FRAUD_CHECK, journeyResponse);

        var expectedStoredVc =
                vcs.stream().filter(vc -> vc != EXPIRED_M1A_EXPERIAN_FRAUD_VC).toList();
        verify(mockSessionCredentialService)
                .persistCredentials(expectedStoredVc, ipvSessionItem.getIpvSessionId(), false);

        verify(ipvSessionItem, never()).setVot(any());
        verify(ipvSessionService, never()).updateIpvSession(any());
        verify(mockEvcsMigrationService, times(0)).migrateExistingIdentity(any(), any());
    }

    @Test
    void
            shouldReturnJourneyRepeatFraudCheckResponseIfExpiredFraudAndFlagIsTrueAndAlsoStoreVcsInEvcs()
                    throws Exception {
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        var vcs =
                List.of(
                        PASSPORT_NON_DCMAW_SUCCESSFUL_VC,
                        M1A_ADDRESS_VC,
                        EXPIRED_M1A_EXPERIAN_FRAUD_VC,
                        vcVerificationM1a(),
                        M1B_DCMAW_VC);
        when(mockVerifiableCredentialService.getVcs(TEST_USER_ID)).thenReturn(vcs);

        when(gpg45ProfileEvaluator.getFirstMatchingProfile(
                        any(), eq(P2.getSupportedGpg45Profiles())))
                .thenReturn(Optional.of(Gpg45Profile.M1B));
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(userIdentityService.checkRequiresAdditionalEvidence(any())).thenReturn(false);
        when(userIdentityService.areVcsCorrelated(any())).thenReturn(true);
        when(configService.enabled(RESET_IDENTITY)).thenReturn(false);
        when(configService.enabled(INHERITED_IDENTITY)).thenReturn(false);
        when(configService.enabled(REPEAT_FRAUD_CHECK)).thenReturn(true);
        when(configService.enabled(EVCS_WRITE_ENABLED)).thenReturn(true);
        when(configService.enabled(P1_JOURNEYS_ENABLED)).thenReturn(false);
        when(configService.getSsmParameter(COMPONENT_ID)).thenReturn("http://ipv/");
        when(configService.getSsmParameter(FRAUD_CHECK_EXPIRY_PERIOD_HOURS)).thenReturn("1");

        JourneyResponse journeyResponse =
                toResponseClass(
                        checkExistingIdentityHandler.handleRequest(event, context),
                        JourneyResponse.class);
        assertEquals(JOURNEY_REPEAT_FRAUD_CHECK, journeyResponse);

        verify(auditService, times(2)).sendAuditEvent(auditEventArgumentCaptor.capture());
        assertEquals(
                AuditEventTypes.IPV_GPG45_PROFILE_MATCHED,
                auditEventArgumentCaptor.getAllValues().get(0).getEventName());
        assertEquals(
                AuditEventTypes.IPV_VCS_MIGRATED,
                auditEventArgumentCaptor.getAllValues().get(1).getEventName());

        var expectedStoredVc =
                vcs.stream().filter(vc -> vc != EXPIRED_M1A_EXPERIAN_FRAUD_VC).toList();
        verify(mockSessionCredentialService)
                .persistCredentials(expectedStoredVc, ipvSessionItem.getIpvSessionId(), false);
        verify(mockEvcsMigrationService).migrateExistingIdentity(TEST_USER_ID, vcs);
    }

    @Test
    void shouldNotReturnJourneyRepeatFraudCheckResponseIfNotExpiredFraudAndFlagIsTrue()
            throws Exception {
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(mockVerifiableCredentialService.getVcs(TEST_USER_ID)).thenReturn(VCS_FROM_STORE);

        when(gpg45ProfileEvaluator.getFirstMatchingProfile(
                        any(), eq(P2.getSupportedGpg45Profiles())))
                .thenReturn(Optional.of(Gpg45Profile.M1B));
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(userIdentityService.checkRequiresAdditionalEvidence(any())).thenReturn(false);
        when(userIdentityService.areVcsCorrelated(any())).thenReturn(true);
        when(configService.enabled(EVCS_WRITE_ENABLED)).thenReturn(false);
        when(configService.enabled(EVCS_READ_ENABLED)).thenReturn(false);
        when(configService.enabled(RESET_IDENTITY)).thenReturn(false);
        when(configService.enabled(INHERITED_IDENTITY)).thenReturn(false);
        when(configService.enabled(REPEAT_FRAUD_CHECK)).thenReturn(true);
        when(configService.enabled(P1_JOURNEYS_ENABLED)).thenReturn(false);
        when(configService.getSsmParameter(COMPONENT_ID)).thenReturn("http://ipv/");
        when(configService.getSsmParameter(FRAUD_CHECK_EXPIRY_PERIOD_HOURS))
                .thenReturn("100000000"); // not the best way to test this

        JourneyResponse journeyResponse =
                toResponseClass(
                        checkExistingIdentityHandler.handleRequest(event, context),
                        JourneyResponse.class);
        assertNotEquals(JOURNEY_REPEAT_FRAUD_CHECK, journeyResponse);

        verify(mockSessionCredentialService)
                .persistCredentials(VCS_FROM_STORE, ipvSessionItem.getIpvSessionId(), false);

        InOrder inOrder = inOrder(ipvSessionItem, ipvSessionService);
        inOrder.verify(ipvSessionItem).setVot(P2);
        inOrder.verify(ipvSessionService).updateIpvSession(ipvSessionItem);
        inOrder.verify(ipvSessionItem, never()).setVot(any());
        assertEquals(P2, ipvSessionItem.getVot());
    }

    private static Stream<Map<String, Object>> votAndVtrCombinationsThatShouldStartIpvJourney() {
        return Stream.of(
                Map.of("vtr", List.of(P2), "operationalCredVot", Optional.empty()),
                Map.of("vtr", List.of(P2), "operationalCredVot", Optional.of(Vot.PCL200)),
                Map.of("vtr", List.of(P2), "operationalCredVot", Optional.of(Vot.PCL250)),
                Map.of("vtr", List.of(P2, Vot.PCL250), "operationalCredVot", Optional.empty()),
                Map.of(
                        "vtr",
                        List.of(P2, Vot.PCL250),
                        "operationalCredVot",
                        Optional.of(Vot.PCL200)),
                Map.of(
                        "vtr",
                        List.of(P2, Vot.PCL250, Vot.PCL200),
                        "operationalCredVot",
                        Optional.empty()));
    }

    private <T> T toResponseClass(Map<String, Object> handlerOutput, Class<T> responseClass) {
        return MAPPER.convertValue(handlerOutput, responseClass);
    }

    private CriResponseItem createCriResponseStoreItem() {
        CriResponseItem criResponseItem = new CriResponseItem();
        criResponseItem.setUserId(TEST_USER_ID);
        criResponseItem.setCredentialIssuer(F2F.getId());
        criResponseItem.setIssuerResponse(PASSPORT_NON_DCMAW_SUCCESSFUL_VC.getVcString());
        criResponseItem.setDateCreated(Instant.now());
        criResponseItem.setStatus(CriResponseService.STATUS_PENDING);
        return criResponseItem;
    }

    private CriResponseItem createCriErrorResponseStoreItem(Instant dateCreated) {
        CriResponseItem criResponseItem = new CriResponseItem();
        criResponseItem.setUserId(TEST_USER_ID);
        criResponseItem.setCredentialIssuer(F2F.getId());
        criResponseItem.setIssuerResponse(PASSPORT_NON_DCMAW_SUCCESSFUL_VC.getVcString());
        criResponseItem.setDateCreated(dateCreated);
        criResponseItem.setStatus(CriResponseService.STATUS_ERROR);
        return criResponseItem;
    }

    private static VerifiableCredential createOperationalProfileVc(Vot vot) throws Exception {
        var testVcClaim = TestVc.builder().evidence(DCMAW_EVIDENCE_VRI_CHECK).build();
        var jwt =
                new SignedJWT(
                        new JWSHeader(JWSAlgorithm.ES256),
                        new JWTClaimsSet.Builder()
                                .claim(VOT_CLAIM_NAME, vot.name())
                                .claim(VC_CLAIM, testVcClaim)
                                .build());
        jwt.sign(jwtSigner);
        return VerifiableCredential.fromValidJwt(
                TEST_USER_ID, HMRC_MIGRATION, SignedJWT.parse(jwt.serialize()));
    }

    private static ECDSASigner createJwtSigner() throws Exception {
        return new ECDSASigner(ECKey.parse(EC_PRIVATE_KEY_JWK).toECPrivateKey());
    }
}
