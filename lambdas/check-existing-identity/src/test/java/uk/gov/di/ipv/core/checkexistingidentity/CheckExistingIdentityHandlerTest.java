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
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.EnumSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.InOrder;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.auditing.AuditEvent;
import uk.gov.di.ipv.core.library.auditing.AuditEventTypes;
import uk.gov.di.ipv.core.library.cimit.exception.CiRetrievalException;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.JourneyErrorResponse;
import uk.gov.di.ipv.core.library.domain.JourneyRequest;
import uk.gov.di.ipv.core.library.domain.JourneyResponse;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.enums.Vot;
import uk.gov.di.ipv.core.library.exceptions.ConfigException;
import uk.gov.di.ipv.core.library.exceptions.UnrecognisedCiException;
import uk.gov.di.ipv.core.library.exceptions.VerifiableCredentialException;
import uk.gov.di.ipv.core.library.gpg45.Gpg45Scores;
import uk.gov.di.ipv.core.library.gpg45.enums.Gpg45Profile;
import uk.gov.di.ipv.core.library.helpers.SecureTokenHelper;
import uk.gov.di.ipv.core.library.helpers.TestVc;
import uk.gov.di.ipv.core.library.journeys.JourneyUris;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.CriResponseItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.CimitService;
import uk.gov.di.ipv.core.library.service.CimitUtilityService;
import uk.gov.di.ipv.core.library.service.ClientOAuthSessionDetailsService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.CriResponseService;
import uk.gov.di.ipv.core.library.service.EvcsService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.service.UserIdentityService;
import uk.gov.di.ipv.core.library.service.VotMatcher;
import uk.gov.di.ipv.core.library.service.VotMatchingResult;
import uk.gov.di.ipv.core.library.testhelpers.unit.LogCollector;
import uk.gov.di.ipv.core.library.verifiablecredential.service.SessionCredentialsService;
import uk.gov.di.model.ContraIndicator;
import uk.gov.di.model.Mitigation;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.StringContains.containsString;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
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
import static uk.gov.di.ipv.core.library.config.CoreFeatureFlag.P1_JOURNEYS_ENABLED;
import static uk.gov.di.ipv.core.library.config.CoreFeatureFlag.REPEAT_FRAUD_CHECK;
import static uk.gov.di.ipv.core.library.config.CoreFeatureFlag.RESET_IDENTITY;
import static uk.gov.di.ipv.core.library.domain.Cri.F2F;
import static uk.gov.di.ipv.core.library.domain.Cri.HMRC_MIGRATION;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_CLAIM;
import static uk.gov.di.ipv.core.library.domain.VocabConstants.VOT_CLAIM_NAME;
import static uk.gov.di.ipv.core.library.enums.EvcsVCState.CURRENT;
import static uk.gov.di.ipv.core.library.enums.EvcsVCState.PENDING_RETURN;
import static uk.gov.di.ipv.core.library.enums.Vot.P1;
import static uk.gov.di.ipv.core.library.enums.Vot.P2;
import static uk.gov.di.ipv.core.library.enums.Vot.PCL200;
import static uk.gov.di.ipv.core.library.enums.Vot.PCL250;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.EC_PRIVATE_KEY_JWK;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.DCMAW_EVIDENCE_VRI_CHECK;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.EXPIRED_M1A_EXPERIAN_FRAUD_VC;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.M1A_ADDRESS_VC;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.M1A_EXPERIAN_FRAUD_VC;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.M1B_DCMAW_VC;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.PASSPORT_NON_DCMAW_SUCCESSFUL_VC;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcDrivingPermit;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcF2fM1a;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcHmrcMigrationPCL200;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcVerificationM1a;
import static uk.gov.di.ipv.core.library.gpg45.enums.Gpg45Profile.M1A;
import static uk.gov.di.ipv.core.library.gpg45.enums.Gpg45Profile.M1B;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_ENHANCED_VERIFICATION_F2F_FAIL_PATH;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_ENHANCED_VERIFICATION_PATH;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_F2F_FAIL_PATH;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_FAIL_WITH_CI_PATH;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_IN_MIGRATION_REUSE_PATH;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_IPV_GPG45_LOW_PATH;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_IPV_GPG45_MEDIUM_PATH;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_OPERATIONAL_PROFILE_REUSE_PATH;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_PENDING_PATH;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_REPEAT_FRAUD_CHECK_PATH;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_REPROVE_IDENTITY_GPG45_LOW_PATH;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_REPROVE_IDENTITY_GPG45_MEDIUM_PATH;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_REUSE_PATH;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_REUSE_WITH_STORE_PATH;

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
    private static final Vot TEST_VOT = P2;
    private static final JourneyResponse JOURNEY_FAIL_WITH_CI =
            new JourneyResponse(JOURNEY_FAIL_WITH_CI_PATH);
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
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final VerifiableCredential gpg45Vc = vcDrivingPermit();
    private static ECDSASigner jwtSigner;
    private static VerifiableCredential pcl200Vc;
    private static VerifiableCredential pcl250Vc;

    @Mock private Context context;
    @Mock private UserIdentityService userIdentityService;
    @Mock private CriResponseService criResponseService;
    @Mock private IpvSessionService ipvSessionService;
    @Mock private ConfigService configService;
    @Mock private AuditService auditService;
    @Mock private ClientOAuthSessionDetailsService clientOAuthSessionDetailsService;
    @Mock private CimitService cimitService;
    @Mock private CimitUtilityService cimitUtilityService;
    @Mock private EvcsService mockEvcsService;
    @Mock private SessionCredentialsService mockSessionCredentialService;
    @Mock private VotMatcher mockVotMatcher;
    @InjectMocks private CheckExistingIdentityHandler checkExistingIdentityHandler;

    @Spy private IpvSessionItem ipvSessionItem;
    @Captor private ArgumentCaptor<AuditEvent> auditEventArgumentCaptor;
    private JourneyRequest event;
    private ClientOAuthSessionItem clientOAuthSessionItem;

    @BeforeAll
    static void setUp() throws Exception {
        jwtSigner = createJwtSigner();
        pcl200Vc = createOperationalProfileVc(PCL200);
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

    @AfterEach
    void checkAuditEventWait() {
        InOrder auditInOrder = inOrder(auditService);
        auditInOrder.verify(auditService).awaitAuditEvents();
        auditInOrder.verifyNoMoreInteractions();
    }

    @Test
    void shouldReturnJourneyNewGpg45MediumIdentityForP2Vtr() throws Exception {
        when(ipvSessionService.getIpvSessionWithRetry(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        JourneyResponse journeyResponse =
                toResponseClass(
                        checkExistingIdentityHandler.handleRequest(event, context),
                        JourneyResponse.class);

        assertEquals(JOURNEY_IPV_GPG45_MEDIUM, journeyResponse);

        verify(auditService, never()).sendAuditEvent(auditEventArgumentCaptor.capture());
        assertEquals(P2, ipvSessionItem.getTargetVot());
    }

    @Test
    void shouldReturnJourneyNewGpg45LowIdentityForP1Vtr() throws Exception {
        when(ipvSessionService.getIpvSessionWithRetry(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        clientOAuthSessionItem.setVtr(List.of(P2.name(), P1.name()));
        when(configService.enabled(P1_JOURNEYS_ENABLED)).thenReturn(true);
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        JourneyResponse journeyResponse =
                toResponseClass(
                        checkExistingIdentityHandler.handleRequest(event, context),
                        JourneyResponse.class);

        assertEquals(JOURNEY_IPV_GPG45_LOW, journeyResponse);

        verify(auditService, never()).sendAuditEvent(auditEventArgumentCaptor.capture());
        assertEquals(P1, ipvSessionItem.getTargetVot());
    }

    @Nested
    @DisplayName("reuse journeys")
    class ReuseJourneys {
        @BeforeEach
        public void reuseSetup() throws Exception {
            when(ipvSessionService.getIpvSessionWithRetry(TEST_SESSION_ID))
                    .thenReturn(ipvSessionItem);
            when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                    .thenReturn(clientOAuthSessionItem);
        }

        @Test
        void shouldUseEvcsService() throws Exception {
            when(mockEvcsService.getVerifiableCredentialsByState(
                            TEST_USER_ID, EVCS_TEST_TOKEN, CURRENT, PENDING_RETURN))
                    .thenReturn(Map.of(CURRENT, List.of(gpg45Vc)));

            checkExistingIdentityHandler.handleRequest(event, context);

            verify(clientOAuthSessionDetailsService).getClientOAuthSession(any());
            verify(mockEvcsService)
                    .getVerifiableCredentialsByState(
                            TEST_USER_ID, EVCS_TEST_TOKEN, CURRENT, PENDING_RETURN);
        }

        @ParameterizedTest
        @EnumSource(names = {"M1A", "M1B", "M2B"})
        void shouldReturnJourneyReuseResponseIfScoresSatisfyP2Gpg45Profile(
                Gpg45Profile matchedProfile) throws Exception {
            var hmrcMigrationVC = vcHmrcMigrationPCL200();
            when(userIdentityService.areVcsCorrelated(any())).thenReturn(true);
            when(mockEvcsService.getVerifiableCredentialsByState(
                            TEST_USER_ID, EVCS_TEST_TOKEN, CURRENT, PENDING_RETURN))
                    .thenReturn(Map.of(CURRENT, List.of(gpg45Vc, hmrcMigrationVC)));
            when(mockVotMatcher.matchFirstVot(
                            List.of(P2), List.of(gpg45Vc, hmrcMigrationVC), List.of(), true))
                    .thenReturn(
                            Optional.of(
                                    new VotMatchingResult(
                                            P2, matchedProfile, Gpg45Scores.builder().build())));

            var journeyResponse =
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

            verify(mockSessionCredentialService)
                    .persistCredentials(List.of(gpg45Vc), ipvSessionItem.getIpvSessionId(), false);

            var inOrder = inOrder(ipvSessionItem, ipvSessionService);
            inOrder.verify(ipvSessionItem).setVot(P2);
            inOrder.verify(ipvSessionService).updateIpvSession(ipvSessionItem);
            inOrder.verify(ipvSessionItem, never()).setVot(any());
            assertEquals(P2, ipvSessionItem.getVot());
        }

        @Test
        void shouldReturnJourneyReuseWithStoreResponseIfIsF2fPendingReturn() throws Exception {
            var vcs = List.of(gpg45Vc, vcF2fM1a());
            when(mockEvcsService.getVerifiableCredentialsByState(
                            TEST_USER_ID, EVCS_TEST_TOKEN, CURRENT, PENDING_RETURN))
                    .thenReturn(Map.of(PENDING_RETURN, new ArrayList<>(vcs)));

            when(criResponseService.getFaceToFaceRequest(TEST_USER_ID))
                    .thenReturn(new CriResponseItem());
            when(mockVotMatcher.matchFirstVot(List.of(P2), vcs, List.of(), true))
                    .thenReturn(
                            Optional.of(
                                    new VotMatchingResult(P2, M1A, Gpg45Scores.builder().build())));
            when(userIdentityService.areVcsCorrelated(any())).thenReturn(true);

            var journeyResponse =
                    toResponseClass(
                            checkExistingIdentityHandler.handleRequest(event, context),
                            JourneyResponse.class);

            assertEquals(JOURNEY_REUSE_WITH_STORE, journeyResponse);
        }

        @Test
        void shouldIncludeCurrentInheritedIdentityInVcBundleWhenPendingReturn() throws Exception {
            var inheritedIdentityVc = vcHmrcMigrationPCL200();
            var f2fVc = vcF2fM1a();

            when(mockEvcsService.getVerifiableCredentialsByState(
                            TEST_USER_ID, EVCS_TEST_TOKEN, CURRENT, PENDING_RETURN))
                    .thenReturn(
                            Map.of(
                                    PENDING_RETURN,
                                    new ArrayList<>(List.of(gpg45Vc, f2fVc)),
                                    CURRENT,
                                    List.of(inheritedIdentityVc)));

            checkExistingIdentityHandler.handleRequest(event, context);

            verify(userIdentityService)
                    .areVcsCorrelated(List.of(gpg45Vc, f2fVc, inheritedIdentityVc));
        }

        @Test // User returning after migration
        void shouldReturnJourneyOpProfileReuseResponseIfPCL200RequestedAndMetWhenNotInMigration()
                throws Exception {
            when(mockEvcsService.getVerifiableCredentialsByState(
                            TEST_USER_ID, EVCS_TEST_TOKEN, CURRENT, PENDING_RETURN))
                    .thenReturn(Map.of(CURRENT, List.of(gpg45Vc, pcl200Vc)));
            when(mockVotMatcher.matchFirstVot(
                            List.of(P2, PCL250, PCL200),
                            List.of(gpg45Vc, pcl200Vc),
                            List.of(),
                            false))
                    .thenReturn(Optional.of(new VotMatchingResult(PCL200, null, null)));
            clientOAuthSessionItem.setVtr(List.of(P2.name(), Vot.PCL250.name(), Vot.PCL200.name()));
            ipvSessionItem.setInheritedIdentityReceivedThisSession(false);

            var journeyResponse =
                    toResponseClass(
                            checkExistingIdentityHandler.handleRequest(event, context),
                            JourneyResponse.class);

            assertEquals(JOURNEY_OP_PROFILE_REUSE, journeyResponse);

            verify(mockSessionCredentialService)
                    .persistCredentials(List.of(pcl200Vc), ipvSessionItem.getIpvSessionId(), false);

            var inOrder = inOrder(ipvSessionItem, ipvSessionService);
            inOrder.verify(ipvSessionItem).setVot(Vot.PCL200);
            inOrder.verify(ipvSessionService).updateIpvSession(ipvSessionItem);
            inOrder.verify(ipvSessionItem, never()).setVot(any());
            assertEquals(PCL200, ipvSessionItem.getVot());
            assertEquals(PCL200, ipvSessionItem.getTargetVot());
        }

        @Test // User returning after migration
        void shouldReturnJourneyOpProfileReuseResponseIfPCL250RequestedAndMetWhenNotInMigration()
                throws Exception {
            when(mockEvcsService.getVerifiableCredentialsByState(
                            TEST_USER_ID, EVCS_TEST_TOKEN, CURRENT, PENDING_RETURN))
                    .thenReturn(Map.of(CURRENT, List.of(gpg45Vc, pcl250Vc)));
            when(mockVotMatcher.matchFirstVot(
                            List.of(P2, PCL250), List.of(gpg45Vc, pcl250Vc), List.of(), false))
                    .thenReturn(Optional.of(new VotMatchingResult(PCL250, null, null)));
            clientOAuthSessionItem.setVtr(List.of(P2.name(), Vot.PCL250.name()));
            ipvSessionItem.setInheritedIdentityReceivedThisSession(false);

            var journeyResponse =
                    toResponseClass(
                            checkExistingIdentityHandler.handleRequest(event, context),
                            JourneyResponse.class);

            assertEquals(JOURNEY_OP_PROFILE_REUSE, journeyResponse);

            verify(mockSessionCredentialService)
                    .persistCredentials(List.of(pcl250Vc), ipvSessionItem.getIpvSessionId(), false);

            var inOrder = inOrder(ipvSessionItem, ipvSessionService);
            inOrder.verify(ipvSessionItem).setVot(Vot.PCL250);
            inOrder.verify(ipvSessionService).updateIpvSession(ipvSessionItem);
            inOrder.verify(ipvSessionItem, never()).setVot(any());
            assertEquals(Vot.PCL250, ipvSessionItem.getVot());
            assertEquals(Vot.PCL250, ipvSessionItem.getTargetVot());
        }

        @Test // User returning after migration
        void shouldReturnJourneyOpProfileReuseResponseIfOpProfileAndPendingF2F() throws Exception {
            when(criResponseService.getFaceToFaceRequest(any())).thenReturn(new CriResponseItem());
            when(mockEvcsService.getVerifiableCredentialsByState(
                            TEST_USER_ID, EVCS_TEST_TOKEN, CURRENT, PENDING_RETURN))
                    .thenReturn(Map.of(CURRENT, List.of(pcl250Vc)));
            when(mockVotMatcher.matchFirstVot(
                            List.of(P2, PCL250), List.of(pcl250Vc), List.of(), false))
                    .thenReturn(Optional.of(new VotMatchingResult(PCL250, null, null)));

            clientOAuthSessionItem.setVtr(List.of(P2.name(), Vot.PCL250.name()));
            ipvSessionItem.setInheritedIdentityReceivedThisSession(false);

            var journeyResponse =
                    toResponseClass(
                            checkExistingIdentityHandler.handleRequest(event, context),
                            JourneyResponse.class);

            assertEquals(JOURNEY_OP_PROFILE_REUSE, journeyResponse);

            var inOrder = inOrder(ipvSessionItem, ipvSessionService);
            inOrder.verify(ipvSessionItem).setVot(Vot.PCL250);
            inOrder.verify(ipvSessionService).updateIpvSession(ipvSessionItem);
            inOrder.verify(ipvSessionItem, never()).setVot(any());
            assertEquals(Vot.PCL250, ipvSessionItem.getVot());
            assertEquals(Vot.PCL250, ipvSessionItem.getTargetVot());
        }

        @Test // User in process of migration
        void shouldReturnJourneyInMigrationReuseResponseIfPCL200RequestedAndMet() throws Exception {
            when(mockEvcsService.getVerifiableCredentialsByState(
                            TEST_USER_ID, EVCS_TEST_TOKEN, CURRENT, PENDING_RETURN))
                    .thenReturn(Map.of(CURRENT, List.of(gpg45Vc, pcl200Vc)));
            when(mockVotMatcher.matchFirstVot(
                            List.of(P2, PCL250, PCL200),
                            List.of(gpg45Vc, pcl200Vc),
                            List.of(),
                            false))
                    .thenReturn(Optional.of(new VotMatchingResult(PCL200, null, null)));
            ipvSessionItem.setInheritedIdentityReceivedThisSession(true);
            clientOAuthSessionItem.setVtr(List.of(P2.name(), Vot.PCL250.name(), PCL200.name()));

            var journeyResponse =
                    toResponseClass(
                            checkExistingIdentityHandler.handleRequest(event, context),
                            JourneyResponse.class);

            assertEquals(JOURNEY_IN_MIGRATION_REUSE, journeyResponse);

            verify(mockSessionCredentialService)
                    .persistCredentials(List.of(pcl200Vc), ipvSessionItem.getIpvSessionId(), true);

            var inOrder = inOrder(ipvSessionItem, ipvSessionService);
            inOrder.verify(ipvSessionItem).setVot(Vot.PCL200);
            inOrder.verify(ipvSessionService).updateIpvSession(ipvSessionItem);
            inOrder.verify(ipvSessionItem, never()).setVot(any());
            assertEquals(PCL200, ipvSessionItem.getVot());
            assertEquals(PCL200, ipvSessionItem.getTargetVot());
        }

        @Test // User in process of migration
        void shouldReturnJourneyInMigrationReuseResponseIfPCL250RequestedAndMet() throws Exception {
            when(mockEvcsService.getVerifiableCredentialsByState(
                            TEST_USER_ID, EVCS_TEST_TOKEN, CURRENT, PENDING_RETURN))
                    .thenReturn(Map.of(CURRENT, List.of(gpg45Vc, pcl250Vc)));
            when(mockVotMatcher.matchFirstVot(
                            List.of(P2, PCL250), List.of(gpg45Vc, pcl250Vc), List.of(), true))
                    .thenReturn(Optional.of(new VotMatchingResult(PCL250, null, null)));

            when(userIdentityService.areVcsCorrelated(any())).thenReturn(true);
            clientOAuthSessionItem.setVtr(List.of(P2.name(), Vot.PCL250.name()));
            ipvSessionItem.setInheritedIdentityReceivedThisSession(true);

            var journeyResponse =
                    toResponseClass(
                            checkExistingIdentityHandler.handleRequest(event, context),
                            JourneyResponse.class);

            assertEquals(JOURNEY_IN_MIGRATION_REUSE, journeyResponse);

            verify(mockSessionCredentialService)
                    .persistCredentials(List.of(pcl250Vc), ipvSessionItem.getIpvSessionId(), true);

            var inOrder = inOrder(ipvSessionItem, ipvSessionService);
            inOrder.verify(ipvSessionItem).setVot(Vot.PCL250);
            inOrder.verify(ipvSessionService).updateIpvSession(ipvSessionItem);
            inOrder.verify(ipvSessionItem, never()).setVot(any());
            assertEquals(Vot.PCL250, ipvSessionItem.getVot());
            assertEquals(Vot.PCL250, ipvSessionItem.getTargetVot());
        }

        @Test
        void shouldReturnErrorResponseIfVcCanNotBeStoredInSessionCredentialTable()
                throws Exception {
            when(mockVotMatcher.matchFirstVot(List.of(P2), List.of(), List.of(), true))
                    .thenReturn(
                            Optional.of(
                                    new VotMatchingResult(P2, M1A, Gpg45Scores.builder().build())));
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
    void shouldReturnF2FFailForF2FCompleteAndVCsDoNotCorrelate() throws Exception {
        when(ipvSessionService.getIpvSessionWithRetry(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(mockEvcsService.getVerifiableCredentialsByState(
                        TEST_USER_ID, EVCS_TEST_TOKEN, CURRENT, PENDING_RETURN))
                .thenReturn(Map.of(PENDING_RETURN, new ArrayList<>(List.of(vcF2fM1a()))));
        when(criResponseService.getFaceToFaceRequest(TEST_USER_ID))
                .thenReturn(createCriResponseStoreItem(CriResponseService.STATUS_PENDING));
        when(userIdentityService.areVcsCorrelated(any())).thenReturn(false);

        clientOAuthSessionItem.setVtr(List.of(Vot.PCL250.name(), PCL200.name(), P2.name()));

        var journeyResponse =
                toResponseClass(
                        checkExistingIdentityHandler.handleRequest(event, context),
                        JourneyResponse.class);

        assertEquals(JOURNEY_F2F_FAIL, journeyResponse);

        verify(auditService, times(1)).sendAuditEvent(auditEventArgumentCaptor.capture());
        assertEquals(
                AuditEventTypes.IPV_F2F_CORRELATION_FAIL,
                auditEventArgumentCaptor.getAllValues().get(0).getEventName());
        verify(clientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());

        verify(ipvSessionItem, never()).setVot(any());
        assertNull(ipvSessionItem.getVot());
        assertEquals(P2, ipvSessionItem.getTargetVot());
    }

    @Test
    void shouldReturnNoMatchResponseIfVCsDoNotCorrelate() throws Exception {
        when(ipvSessionService.getIpvSessionWithRetry(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(mockEvcsService.getVerifiableCredentialsByState(
                        TEST_USER_ID, EVCS_TEST_TOKEN, CURRENT, PENDING_RETURN))
                .thenReturn(Map.of(CURRENT, List.of(vcF2fM1a())));
        when(userIdentityService.areVcsCorrelated(any())).thenReturn(false);

        clientOAuthSessionItem.setVtr(List.of(Vot.PCL250.name(), PCL200.name(), P2.name()));

        JourneyResponse journeyResponse =
                toResponseClass(
                        checkExistingIdentityHandler.handleRequest(event, context),
                        JourneyResponse.class);

        assertEquals(JOURNEY_IPV_GPG45_MEDIUM, journeyResponse);

        verify(clientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());

        verify(ipvSessionItem, never()).setVot(any());
        assertNull(ipvSessionItem.getVot());
        assertEquals(P2, ipvSessionItem.getTargetVot());
    }

    @ParameterizedTest
    @MethodSource("votAndVtrCombinationsThatShouldStartIpvJourney")
    void shouldReturnJourneyIpvGpg45MediumResponseIfNoProfileAttainsVot(
            List<String> vtr, Optional<Vot> vot) throws Exception {
        when(ipvSessionService.getIpvSessionWithRetry(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(criResponseService.getFaceToFaceRequest(TEST_USER_ID)).thenReturn(null);

        var credentials = new ArrayList<VerifiableCredential>();
        if (vot.isPresent()) {
            credentials.add(createOperationalProfileVc(vot.get()));
        }
        when(mockEvcsService.getVerifiableCredentialsByState(
                        TEST_USER_ID, EVCS_TEST_TOKEN, CURRENT, PENDING_RETURN))
                .thenReturn(Map.of(CURRENT, credentials));
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        clientOAuthSessionItem.setVtr(vtr);

        var journeyResponse =
                toResponseClass(
                        checkExistingIdentityHandler.handleRequest(event, context),
                        JourneyResponse.class);

        assertEquals(JOURNEY_IPV_GPG45_MEDIUM, journeyResponse);

        verify(ipvSessionItem, never()).setVot(any());
    }

    @Test
    void shouldReturnJourneyIpvGpg45MediumResponseIfScoresDoNotSatisfyP2Gpg45Profile()
            throws Exception {
        when(ipvSessionService.getIpvSessionWithRetry(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(mockEvcsService.getVerifiableCredentialsByState(
                        TEST_USER_ID, EVCS_TEST_TOKEN, CURRENT, PENDING_RETURN))
                .thenReturn(Map.of(CURRENT, VCS_FROM_STORE));
        when(criResponseService.getFaceToFaceRequest(TEST_USER_ID)).thenReturn(null);
        when(userIdentityService.areVcsCorrelated(any())).thenReturn(true);
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        var journeyResponse =
                toResponseClass(
                        checkExistingIdentityHandler.handleRequest(event, context),
                        JourneyResponse.class);

        assertEquals(JOURNEY_IPV_GPG45_MEDIUM, journeyResponse);

        verify(clientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());

        verify(ipvSessionItem, never()).setVot(any());
        assertNull(ipvSessionItem.getVot());
        assertEquals(P2, ipvSessionItem.getTargetVot());
    }

    @Test
    void shouldNotSendAuditEventIfNewUser() throws Exception {
        when(ipvSessionService.getIpvSessionWithRetry(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(criResponseService.getFaceToFaceRequest(TEST_USER_ID)).thenReturn(null);
        when(userIdentityService.areVcsCorrelated(any())).thenReturn(true);
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        var journeyResponse =
                toResponseClass(
                        checkExistingIdentityHandler.handleRequest(event, context),
                        JourneyResponse.class);

        assertEquals(JOURNEY_IPV_GPG45_MEDIUM_PATH, journeyResponse.getJourney());

        verify(auditService, never()).sendAuditEvent(auditEventArgumentCaptor.capture());
        verify(clientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());

        verify(ipvSessionItem, never()).setVot(any());
        assertNull(ipvSessionItem.getVot());
        assertEquals(P2, ipvSessionItem.getTargetVot());
    }

    @Test
    void shouldReturn400IfSessionIdNotInHeader() throws Exception {
        var eventWithoutHeaders = JourneyRequest.builder().build();

        var journeyResponse =
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
    void shouldReturnPendingResponseIfFaceToFaceVerificationIsPending() throws Exception {
        when(ipvSessionService.getIpvSessionWithRetry(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        var criResponseItem = createCriResponseStoreItem(CriResponseService.STATUS_PENDING);
        when(criResponseService.getFaceToFaceRequest(TEST_USER_ID)).thenReturn(criResponseItem);
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        var journeyResponse =
                toResponseClass(
                        checkExistingIdentityHandler.handleRequest(event, context),
                        JourneyResponse.class);

        assertEquals(JOURNEY_PENDING, journeyResponse);

        verify(ipvSessionItem, never()).setVot(any());
        assertNull(ipvSessionItem.getVot());
        assertEquals(P2, ipvSessionItem.getTargetVot());
    }

    @Test
    void shouldReturnPendingResponseIfFaceToFaceVerificationIsPendingAndBreachingCi()
            throws Exception {
        when(ipvSessionService.getIpvSessionWithRetry(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        var criResponseItem = createCriResponseStoreItem(CriResponseService.STATUS_PENDING);
        when(criResponseService.getFaceToFaceRequest(TEST_USER_ID)).thenReturn(criResponseItem);
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(cimitUtilityService.getMitigationJourneyIfBreaching(any(), eq(TEST_VOT)))
                .thenReturn(Optional.of(JOURNEY_FAIL_WITH_CI));

        var journeyResponse =
                toResponseClass(
                        checkExistingIdentityHandler.handleRequest(event, context),
                        JourneyResponse.class);

        assertEquals(JOURNEY_PENDING, journeyResponse);

        verify(ipvSessionItem, never()).setVot(any());
        assertNull(ipvSessionItem.getVot());
        assertEquals(P2, ipvSessionItem.getTargetVot());
    }

    @Test
    void shouldReturnFailResponseIfFaceToFaceVerificationIsError() throws Exception {
        when(ipvSessionService.getIpvSessionWithRetry(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        var criResponseItem = createCriErrorResponseStoreItem(Instant.now());
        when(criResponseService.getFaceToFaceRequest(TEST_USER_ID)).thenReturn(criResponseItem);
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        var journeyResponse =
                toResponseClass(
                        checkExistingIdentityHandler.handleRequest(event, context),
                        JourneyResponse.class);

        assertEquals(JOURNEY_F2F_FAIL, journeyResponse);

        verify(ipvSessionItem, never()).setVot(any());
        assertNull(ipvSessionItem.getVot());
        assertEquals(P2, ipvSessionItem.getTargetVot());
    }

    @Test
    void shouldReturnFailResponseIfFaceToFaceVerificationIsAbandon() throws Exception {
        when(ipvSessionService.getIpvSessionWithRetry(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        var criResponseItem = createCriResponseStoreItem(CriResponseService.STATUS_ABANDON);
        when(criResponseService.getFaceToFaceRequest(TEST_USER_ID)).thenReturn(criResponseItem);
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        var journeyResponse =
                toResponseClass(
                        checkExistingIdentityHandler.handleRequest(event, context),
                        JourneyResponse.class);

        assertEquals(JOURNEY_F2F_FAIL, journeyResponse);

        verify(ipvSessionItem, never()).setVot(any());
        assertNull(ipvSessionItem.getVot());
        assertEquals(P2, ipvSessionItem.getTargetVot());
    }

    @Test
    void shouldReturnFailResponseForFaceToFaceVerificationIfNoMatchedProfile() throws Exception {
        when(ipvSessionService.getIpvSessionWithRetry(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(mockEvcsService.getVerifiableCredentialsByState(
                        TEST_USER_ID, EVCS_TEST_TOKEN, CURRENT, PENDING_RETURN))
                .thenReturn(Map.of(PENDING_RETURN, new ArrayList<>(List.of(vcF2fM1a()))));
        var criResponseItem = createCriResponseStoreItem(CriResponseService.STATUS_PENDING);
        when(criResponseService.getFaceToFaceRequest(TEST_USER_ID)).thenReturn(criResponseItem);
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(userIdentityService.areVcsCorrelated(any())).thenReturn(true);

        var journeyResponse =
                toResponseClass(
                        checkExistingIdentityHandler.handleRequest(event, context),
                        JourneyResponse.class);

        verify(auditService, times(1)).sendAuditEvent(auditEventArgumentCaptor.capture());
        assertEquals(
                AuditEventTypes.IPV_F2F_PROFILE_NOT_MET_FAIL,
                auditEventArgumentCaptor.getAllValues().get(0).getEventName());

        assertEquals(JOURNEY_F2F_FAIL, journeyResponse);

        verify(ipvSessionItem, never()).setVot(any());
        assertNull(ipvSessionItem.getVot());
        assertEquals(P2, ipvSessionItem.getTargetVot());
    }

    @Test
    void shouldReturnFailResponseForFaceToFaceIfVCsDoNotCorrelate() throws Exception {
        when(ipvSessionService.getIpvSessionWithRetry(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(mockEvcsService.getVerifiableCredentialsByState(
                        TEST_USER_ID, EVCS_TEST_TOKEN, CURRENT, PENDING_RETURN))
                .thenReturn(Map.of(PENDING_RETURN, new ArrayList<>(List.of(vcF2fM1a()))));
        var criResponseItem = createCriResponseStoreItem(CriResponseService.STATUS_PENDING);
        when(criResponseService.getFaceToFaceRequest(TEST_USER_ID)).thenReturn(criResponseItem);
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(userIdentityService.areVcsCorrelated(any())).thenReturn(false);

        var journeyResponse =
                toResponseClass(
                        checkExistingIdentityHandler.handleRequest(event, context),
                        JourneyResponse.class);

        verify(auditService, times(1)).sendAuditEvent(auditEventArgumentCaptor.capture());
        assertEquals(
                AuditEventTypes.IPV_F2F_CORRELATION_FAIL,
                auditEventArgumentCaptor.getAllValues().get(0).getEventName());
        assertEquals(JOURNEY_F2F_FAIL, journeyResponse);

        verify(ipvSessionItem, never()).setVot(any());
        assertNull(ipvSessionItem.getVot());
        assertEquals(P2, ipvSessionItem.getTargetVot());
    }

    @Test
    void shouldReturnJourneyIpvGpg45MediumIfDataDoesNotCorrelateAndNotF2F() throws Exception {
        when(ipvSessionService.getIpvSessionWithRetry(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(mockEvcsService.getVerifiableCredentialsByState(
                        TEST_USER_ID, EVCS_TEST_TOKEN, CURRENT, PENDING_RETURN))
                .thenReturn(Map.of(PENDING_RETURN, new ArrayList<>(List.of(vcF2fM1a()))));
        when(criResponseService.getFaceToFaceRequest(TEST_USER_ID)).thenReturn(null);
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        var journeyResponse =
                toResponseClass(
                        checkExistingIdentityHandler.handleRequest(event, context),
                        JourneyResponse.class);

        assertEquals(JOURNEY_IPV_GPG45_MEDIUM, journeyResponse);

        verify(ipvSessionItem, never()).setVot(any());
        assertNull(ipvSessionItem.getVot());
        assertEquals(P2, ipvSessionItem.getTargetVot());
    }

    @Test
    void shouldReturnCiJourneyResponseIfPresent() throws Exception {
        var testJourneyResponse = "/journey/test-response";

        when(ipvSessionService.getIpvSessionWithRetry(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(cimitService.getContraIndicators(TEST_USER_ID, TEST_JOURNEY_ID, TEST_CLIENT_SOURCE_IP))
                .thenReturn(List.of());
        when(cimitUtilityService.getMitigationJourneyIfBreaching(any(), eq(TEST_VOT)))
                .thenReturn(Optional.of(new JourneyResponse(testJourneyResponse)));

        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        var response =
                toResponseClass(
                        checkExistingIdentityHandler.handleRequest(event, context),
                        JourneyResponse.class);

        assertEquals(testJourneyResponse, response.getJourney());
        assertEquals(P2, ipvSessionItem.getTargetVot());
    }

    @Test
    void shouldReturnFailWithCiJourneyResponseForCiBreach() throws Exception {
        when(ipvSessionService.getIpvSessionWithRetry(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(cimitService.getContraIndicators(TEST_USER_ID, TEST_JOURNEY_ID, TEST_CLIENT_SOURCE_IP))
                .thenReturn(List.of());
        when(cimitUtilityService.getMitigationJourneyIfBreaching(any(), eq(TEST_VOT)))
                .thenReturn(Optional.of(JOURNEY_FAIL_WITH_CI));

        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        var response =
                toResponseClass(
                        checkExistingIdentityHandler.handleRequest(event, context),
                        JourneyResponse.class);

        assertEquals(JOURNEY_FAIL_WITH_CI_PATH, response.getJourney());
        assertEquals(P2, ipvSessionItem.getTargetVot());
    }

    @Test
    void shouldReturn500IfFailedToRetrieveCisFromStorageSystem() throws Exception {
        when(ipvSessionService.getIpvSessionWithRetry(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(cimitService.getContraIndicators(anyString(), anyString(), anyString()))
                .thenThrow(CiRetrievalException.class);
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        var response =
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
        when(ipvSessionService.getIpvSessionWithRetry(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(cimitUtilityService.getMitigationJourneyIfBreaching(any(), eq(TEST_VOT)))
                .thenThrow(new ConfigException("Failed to get cimit config"));

        var response =
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
        when(ipvSessionService.getIpvSessionWithRetry(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(cimitService.getContraIndicators(TEST_USER_ID, TEST_JOURNEY_ID, TEST_CLIENT_SOURCE_IP))
                .thenThrow(new UnrecognisedCiException("Unrecognised CI"));

        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        var response =
                toResponseClass(
                        checkExistingIdentityHandler.handleRequest(event, context),
                        JourneyErrorResponse.class);

        assertEquals(JourneyUris.JOURNEY_ERROR_PATH, response.getJourney());
        assertEquals(HttpStatus.SC_INTERNAL_SERVER_ERROR, response.getStatusCode());
        assertEquals(ErrorResponse.UNRECOGNISED_CI_CODE.getCode(), response.getCode());
        assertEquals(ErrorResponse.UNRECOGNISED_CI_CODE.getMessage(), response.getMessage());
    }

    @Test
    void
            shouldReturnJourneyFailedWithCiIfTrueCiMitigationJourneyStepPresentAndNoMitigationJourneyStep()
                    throws Exception {
        when(ipvSessionService.getIpvSessionWithRetry(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(cimitService.getContraIndicators(TEST_USER_ID, TEST_JOURNEY_ID, TEST_CLIENT_SOURCE_IP))
                .thenReturn(List.of());
        when(cimitUtilityService.getMitigationJourneyIfBreaching(any(), eq(TEST_VOT)))
                .thenReturn(Optional.of(JOURNEY_FAIL_WITH_CI));

        var journeyResponse =
                toResponseClass(
                        checkExistingIdentityHandler.handleRequest(event, context),
                        JourneyResponse.class);

        assertEquals(JOURNEY_FAIL_WITH_CI_PATH, journeyResponse.getJourney());
    }

    @Test
    void shouldReturnReproveP2JourneyStepResponseIfResetIdentityTrue() throws Exception {
        when(ipvSessionService.getIpvSessionWithRetry(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(cimitService.getContraIndicators(TEST_USER_ID, TEST_JOURNEY_ID, TEST_CLIENT_SOURCE_IP))
                .thenReturn(List.of());
        when(configService.enabled(RESET_IDENTITY)).thenReturn(true);

        var journeyResponse =
                toResponseClass(
                        checkExistingIdentityHandler.handleRequest(event, context),
                        JourneyResponse.class);

        assertEquals(JOURNEY_REPROVE_IDENTITY_GPG45_MEDIUM_PATH, journeyResponse.getJourney());
        assertEquals(P2, ipvSessionItem.getTargetVot());
    }

    @Test
    void shouldReturnReproveP1JourneyStepResponseIfResetIdentityTrueAndP1InVtr() throws Exception {
        when(ipvSessionService.getIpvSessionWithRetry(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        clientOAuthSessionItem.setVtr(List.of(P2.name(), P1.name()));
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(cimitService.getContraIndicators(TEST_USER_ID, TEST_JOURNEY_ID, TEST_CLIENT_SOURCE_IP))
                .thenReturn(List.of());
        when(configService.enabled(RESET_IDENTITY)).thenReturn(true);
        when(configService.enabled(P1_JOURNEYS_ENABLED)).thenReturn(true);

        var journeyResponse =
                toResponseClass(
                        checkExistingIdentityHandler.handleRequest(event, context),
                        JourneyResponse.class);

        assertEquals(JOURNEY_REPROVE_IDENTITY_GPG45_LOW_PATH, journeyResponse.getJourney());
        assertEquals(P1, ipvSessionItem.getTargetVot());
    }

    @Test
    void shouldReturnSameMitigationJourneyWhenCiAlreadyMitigated() throws Exception {
        var journey = "some_mitigation";
        var mitigatedCI = new ContraIndicator();
        mitigatedCI.setCode("test_code");
        mitigatedCI.setMitigation(List.of(new Mitigation()));
        var testContraIndicators = List.of(mitigatedCI);

        when(ipvSessionService.getIpvSessionWithRetry(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(cimitService.getContraIndicators(TEST_USER_ID, TEST_JOURNEY_ID, TEST_CLIENT_SOURCE_IP))
                .thenReturn(testContraIndicators);
        when(cimitUtilityService.getMitigationJourneyIfBreaching(testContraIndicators, TEST_VOT))
                .thenReturn(Optional.empty());

        when(cimitUtilityService.hasMitigatedContraIndicator(testContraIndicators))
                .thenReturn(Optional.of(mitigatedCI));
        when(cimitUtilityService.getMitigatedCiJourneyResponse(mitigatedCI))
                .thenReturn(Optional.of(new JourneyResponse(journey)));

        var journeyResponse =
                toResponseClass(
                        checkExistingIdentityHandler.handleRequest(event, context),
                        JourneyResponse.class);

        assertEquals(journey, journeyResponse.getJourney());
    }

    @Test
    void shouldReturnSameJourneyMitigationWhenCiAlreadyMitigatedF2F() throws Exception {
        var mitigatedCI = new ContraIndicator();
        mitigatedCI.setCode("test_code");
        mitigatedCI.setMitigation(List.of(new Mitigation()));
        var testContraIndicators = List.of(mitigatedCI);

        when(ipvSessionService.getIpvSessionWithRetry(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(mockEvcsService.getVerifiableCredentialsByState(
                        TEST_USER_ID, EVCS_TEST_TOKEN, CURRENT, PENDING_RETURN))
                .thenReturn(Map.of(PENDING_RETURN, new ArrayList<>(List.of(vcF2fM1a()))));
        var criResponseItem = createCriResponseStoreItem(CriResponseService.STATUS_PENDING);
        when(criResponseService.getFaceToFaceRequest(TEST_USER_ID)).thenReturn(criResponseItem);
        when(cimitService.getContraIndicators(TEST_USER_ID, TEST_JOURNEY_ID, TEST_CLIENT_SOURCE_IP))
                .thenReturn(testContraIndicators);
        when(cimitUtilityService.getMitigationJourneyIfBreaching(testContraIndicators, TEST_VOT))
                .thenReturn(Optional.empty());

        when(cimitUtilityService.hasMitigatedContraIndicator(testContraIndicators))
                .thenReturn(Optional.of(mitigatedCI));
        when(cimitUtilityService.getMitigatedCiJourneyResponse(mitigatedCI))
                .thenReturn(Optional.of(new JourneyResponse(JOURNEY_ENHANCED_VERIFICATION_PATH)));

        var journeyResponse =
                toResponseClass(
                        checkExistingIdentityHandler.handleRequest(event, context),
                        JourneyResponse.class);

        assertEquals(JOURNEY_ENHANCED_VERIFICATION_F2F_FAIL_PATH, journeyResponse.getJourney());
    }

    @Test
    void
            shouldReturnErrorResponseIfNoMitigationRouteFoundForAlreadyMitigatedCiWhenBuildingF2FNoMatchResponse()
                    throws Exception {
        var mitigatedCI = new ContraIndicator();
        mitigatedCI.setCode("test_code");
        mitigatedCI.setMitigation(List.of(new Mitigation()));
        var testContraIndicators = List.of(mitigatedCI);

        when(ipvSessionService.getIpvSessionWithRetry(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(mockEvcsService.getVerifiableCredentialsByState(
                        TEST_USER_ID, EVCS_TEST_TOKEN, CURRENT, PENDING_RETURN))
                .thenReturn(Map.of(PENDING_RETURN, new ArrayList<>(List.of(vcF2fM1a()))));
        var criResponseItem = createCriResponseStoreItem(CriResponseService.STATUS_PENDING);
        when(criResponseService.getFaceToFaceRequest(TEST_USER_ID)).thenReturn(criResponseItem);
        when(cimitService.getContraIndicators(TEST_USER_ID, TEST_JOURNEY_ID, TEST_CLIENT_SOURCE_IP))
                .thenReturn(testContraIndicators);
        when(cimitUtilityService.getMitigationJourneyIfBreaching(testContraIndicators, TEST_VOT))
                .thenReturn(Optional.empty());

        when(cimitUtilityService.hasMitigatedContraIndicator(testContraIndicators))
                .thenReturn(Optional.of(mitigatedCI));
        when(cimitUtilityService.getMitigatedCiJourneyResponse(mitigatedCI))
                .thenReturn(Optional.empty());

        var response =
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
        var mitigatedCI = new ContraIndicator();
        mitigatedCI.setCode("test_code");
        mitigatedCI.setMitigation(List.of(new Mitigation()));
        var testContraIndicators = List.of(mitigatedCI);

        when(ipvSessionService.getIpvSessionWithRetry(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(mockEvcsService.getVerifiableCredentialsByState(
                        TEST_USER_ID, EVCS_TEST_TOKEN, CURRENT, PENDING_RETURN))
                .thenReturn(Map.of(PENDING_RETURN, new ArrayList<>(List.of(vcF2fM1a()))));
        var criResponseItem = createCriResponseStoreItem(CriResponseService.STATUS_PENDING);
        when(criResponseService.getFaceToFaceRequest(TEST_USER_ID)).thenReturn(criResponseItem);
        when(cimitService.getContraIndicators(TEST_USER_ID, TEST_JOURNEY_ID, TEST_CLIENT_SOURCE_IP))
                .thenReturn(testContraIndicators);
        when(cimitUtilityService.getMitigationJourneyIfBreaching(testContraIndicators, TEST_VOT))
                .thenReturn(Optional.empty());

        when(cimitUtilityService.hasMitigatedContraIndicator(testContraIndicators))
                .thenReturn(Optional.of(mitigatedCI));
        when(cimitUtilityService.getMitigatedCiJourneyResponse(mitigatedCI))
                .thenReturn(Optional.of(new JourneyResponse(journey)));

        var response =
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
        when(ipvSessionService.getIpvSessionWithRetry(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        var vcs =
                List.of(
                        PASSPORT_NON_DCMAW_SUCCESSFUL_VC,
                        M1A_ADDRESS_VC,
                        EXPIRED_M1A_EXPERIAN_FRAUD_VC,
                        vcVerificationM1a(),
                        M1B_DCMAW_VC);
        when(mockEvcsService.getVerifiableCredentialsByState(
                        TEST_USER_ID, EVCS_TEST_TOKEN, CURRENT, PENDING_RETURN))
                .thenReturn(Map.of(CURRENT, vcs));

        when(mockVotMatcher.matchFirstVot(List.of(P2), vcs, List.of(), true))
                .thenReturn(
                        Optional.of(new VotMatchingResult(P2, M1B, Gpg45Scores.builder().build())));
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(userIdentityService.areVcsCorrelated(any())).thenReturn(true);
        when(configService.enabled(RESET_IDENTITY)).thenReturn(false);
        when(configService.enabled(REPEAT_FRAUD_CHECK)).thenReturn(true);
        when(configService.getParameter(COMPONENT_ID)).thenReturn("http://ipv/");
        when(configService.getParameter(FRAUD_CHECK_EXPIRY_PERIOD_HOURS)).thenReturn("1");

        var journeyResponse =
                toResponseClass(
                        checkExistingIdentityHandler.handleRequest(event, context),
                        JourneyResponse.class);
        assertEquals(JOURNEY_REPEAT_FRAUD_CHECK, journeyResponse);

        var expectedStoredVc =
                vcs.stream().filter(vc -> vc != EXPIRED_M1A_EXPERIAN_FRAUD_VC).toList();
        verify(mockSessionCredentialService)
                .persistCredentials(expectedStoredVc, ipvSessionItem.getIpvSessionId(), false);

        verify(ipvSessionItem, never()).setVot(any());
        assertEquals(P2, ipvSessionItem.getTargetVot());
    }

    @Test
    void shouldNotReturnJourneyRepeatFraudCheckResponseIfNotExpiredFraudAndFlagIsTrue()
            throws Exception {
        when(ipvSessionService.getIpvSessionWithRetry(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(mockEvcsService.getVerifiableCredentialsByState(
                        TEST_USER_ID, EVCS_TEST_TOKEN, CURRENT, PENDING_RETURN))
                .thenReturn(Map.of(CURRENT, VCS_FROM_STORE));

        when(mockVotMatcher.matchFirstVot(List.of(P2), VCS_FROM_STORE, List.of(), true))
                .thenReturn(
                        Optional.of(new VotMatchingResult(P2, M1B, Gpg45Scores.builder().build())));

        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(userIdentityService.areVcsCorrelated(any())).thenReturn(true);
        when(configService.enabled(RESET_IDENTITY)).thenReturn(false);
        when(configService.enabled(REPEAT_FRAUD_CHECK)).thenReturn(true);
        when(configService.getParameter(COMPONENT_ID)).thenReturn("http://ipv/");
        when(configService.getParameter(FRAUD_CHECK_EXPIRY_PERIOD_HOURS))
                .thenReturn("100000000"); // not the best way to test this

        var journeyResponse =
                toResponseClass(
                        checkExistingIdentityHandler.handleRequest(event, context),
                        JourneyResponse.class);
        assertNotEquals(JOURNEY_REPEAT_FRAUD_CHECK, journeyResponse);

        verify(mockSessionCredentialService)
                .persistCredentials(VCS_FROM_STORE, ipvSessionItem.getIpvSessionId(), false);

        var inOrder = inOrder(ipvSessionItem, ipvSessionService);
        inOrder.verify(ipvSessionItem).setVot(P2);
        inOrder.verify(ipvSessionService).updateIpvSession(ipvSessionItem);
        inOrder.verify(ipvSessionItem, never()).setVot(any());
        assertEquals(P2, ipvSessionItem.getVot());
        assertEquals(P2, ipvSessionItem.getTargetVot());
    }

    @Test
    void shouldLogRuntimeExceptionsAndRethrow() throws Exception {
        // Arrange
        when(ipvSessionService.getIpvSessionWithRetry(anyString()))
                .thenThrow(new RuntimeException("Test error"));

        var logCollector = LogCollector.getLogCollectorFor(CheckExistingIdentityHandler.class);

        // Act
        var thrown =
                assertThrows(
                        Exception.class,
                        () -> checkExistingIdentityHandler.handleRequest(event, context),
                        "Expected handleRequest() to throw, but it didn't");

        // Assert
        assertEquals("Test error", thrown.getMessage());
        var logMessage = logCollector.getLogMessages().get(0);
        assertThat(logMessage, containsString("Unhandled lambda exception"));
        assertThat(logMessage, containsString("Test error"));
    }

    private static Stream<Arguments> votAndVtrCombinationsThatShouldStartIpvJourney() {
        return Stream.of(
                Arguments.of(List.of("P2"), Optional.empty()),
                Arguments.of(List.of("P2"), Optional.of(PCL200)),
                Arguments.of(List.of("P2"), Optional.of(Vot.PCL250)),
                Arguments.of(List.of("P2", "PCL250"), Optional.empty()),
                Arguments.of(List.of("P2", "PCL250"), Optional.of(PCL200)),
                Arguments.of(List.of("P2", "PCL250", "PCL200"), Optional.empty()));
    }

    private <T> T toResponseClass(Map<String, Object> handlerOutput, Class<T> responseClass) {
        return OBJECT_MAPPER.convertValue(handlerOutput, responseClass);
    }

    private CriResponseItem createCriResponseStoreItem(String criResponseStatus) {
        CriResponseItem criResponseItem = new CriResponseItem();
        criResponseItem.setUserId(TEST_USER_ID);
        criResponseItem.setCredentialIssuer(F2F.getId());
        criResponseItem.setIssuerResponse(PASSPORT_NON_DCMAW_SUCCESSFUL_VC.getVcString());
        criResponseItem.setDateCreated(Instant.now());
        criResponseItem.setStatus(criResponseStatus);
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
                                .claim(VC_CLAIM, OBJECT_MAPPER.convertValue(testVcClaim, Map.class))
                                .build());
        jwt.sign(jwtSigner);
        return VerifiableCredential.fromValidJwt(
                TEST_USER_ID, HMRC_MIGRATION, SignedJWT.parse(jwt.serialize()));
    }

    private static ECDSASigner createJwtSigner() throws Exception {
        return new ECDSASigner(ECKey.parse(EC_PRIVATE_KEY_JWK).toECPrivateKey());
    }
}
