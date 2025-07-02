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
import org.mockito.Mockito;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;
import software.amazon.awssdk.http.HttpStatusCode;
import uk.gov.di.ipv.core.library.auditing.AuditEvent;
import uk.gov.di.ipv.core.library.auditing.AuditEventTypes;
import uk.gov.di.ipv.core.library.auditing.extension.AuditExtensionPreviousIpvSessionId;
import uk.gov.di.ipv.core.library.cimit.exception.CiRetrievalException;
import uk.gov.di.ipv.core.library.cimit.service.CimitService;
import uk.gov.di.ipv.core.library.criresponse.domain.AsyncCriStatus;
import uk.gov.di.ipv.core.library.criresponse.service.CriResponseService;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.JourneyErrorResponse;
import uk.gov.di.ipv.core.library.domain.JourneyRequest;
import uk.gov.di.ipv.core.library.domain.JourneyResponse;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.enums.Vot;
import uk.gov.di.ipv.core.library.evcs.exception.EvcsServiceException;
import uk.gov.di.ipv.core.library.evcs.service.EvcsService;
import uk.gov.di.ipv.core.library.exceptions.CiExtractionException;
import uk.gov.di.ipv.core.library.exceptions.ConfigException;
import uk.gov.di.ipv.core.library.exceptions.CredentialParseException;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.core.library.exceptions.IpvSessionNotFoundException;
import uk.gov.di.ipv.core.library.exceptions.UnrecognisedCiException;
import uk.gov.di.ipv.core.library.exceptions.VerifiableCredentialException;
import uk.gov.di.ipv.core.library.gpg45.Gpg45Scores;
import uk.gov.di.ipv.core.library.gpg45.enums.Gpg45Profile;
import uk.gov.di.ipv.core.library.helpers.SecureTokenHelper;
import uk.gov.di.ipv.core.library.journeys.JourneyUris;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.CriOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.CriResponseItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.CimitUtilityService;
import uk.gov.di.ipv.core.library.service.ClientOAuthSessionDetailsService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.CriOAuthSessionService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.testhelpers.unit.LogCollector;
import uk.gov.di.ipv.core.library.useridentity.service.UserIdentityService;
import uk.gov.di.ipv.core.library.useridentity.service.VotMatcher;
import uk.gov.di.ipv.core.library.useridentity.service.VotMatchingResult;
import uk.gov.di.ipv.core.library.verifiablecredential.service.SessionCredentialsService;
import uk.gov.di.model.ContraIndicator;
import uk.gov.di.model.Mitigation;

import java.text.ParseException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;

import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.StringContains.containsString;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.COMPONENT_ID;
import static uk.gov.di.ipv.core.library.config.ConfigurationVariable.FRAUD_CHECK_EXPIRY_PERIOD_HOURS;
import static uk.gov.di.ipv.core.library.config.CoreFeatureFlag.P1_JOURNEYS_ENABLED;
import static uk.gov.di.ipv.core.library.config.CoreFeatureFlag.REPEAT_FRAUD_CHECK;
import static uk.gov.di.ipv.core.library.config.CoreFeatureFlag.RESET_IDENTITY;
import static uk.gov.di.ipv.core.library.domain.Cri.DCMAW_ASYNC;
import static uk.gov.di.ipv.core.library.domain.Cri.F2F;
import static uk.gov.di.ipv.core.library.domain.Cri.HMRC_MIGRATION;
import static uk.gov.di.ipv.core.library.domain.VerifiableCredentialConstants.VC_CLAIM;
import static uk.gov.di.ipv.core.library.domain.VocabConstants.VOT_CLAIM_NAME;
import static uk.gov.di.ipv.core.library.enums.Vot.P1;
import static uk.gov.di.ipv.core.library.enums.Vot.P2;
import static uk.gov.di.ipv.core.library.enums.Vot.PCL200;
import static uk.gov.di.ipv.core.library.enums.Vot.PCL250;
import static uk.gov.di.ipv.core.library.evcs.enums.EvcsVCState.CURRENT;
import static uk.gov.di.ipv.core.library.evcs.enums.EvcsVCState.PENDING_RETURN;
import static uk.gov.di.ipv.core.library.fixtures.TestFixtures.EC_PRIVATE_KEY_JWK;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcAddressM1a;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcClaimDcmawPassport;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcDcmawAsyncDrivingPermitDva;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcDcmawDrivingPermitDvaM1b;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcExperianFraudM1a;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcExperianFraudM1aExpired;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcExperianKbvM1a;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcF2fPassportPhotoM1a;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcHmrcMigrationPCL200;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcWebDrivingPermitDvaValid;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcWebPassportSuccessful;
import static uk.gov.di.ipv.core.library.gpg45.enums.Gpg45Profile.M1A;
import static uk.gov.di.ipv.core.library.gpg45.enums.Gpg45Profile.M1B;
import static uk.gov.di.ipv.core.library.journeys.Events.ENHANCED_VERIFICATION_EVENT;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_DCMAW_ASYNC_VC_RECEIVED_LOW_PATH;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_DCMAW_ASYNC_VC_RECEIVED_MEDIUM_PATH;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_F2F_FAIL_PATH;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_F2F_PENDING_PATH;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_FAIL_WITH_CI_PATH;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_IN_MIGRATION_REUSE_PATH;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_IPV_GPG45_LOW_PATH;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_IPV_GPG45_MEDIUM_PATH;
import static uk.gov.di.ipv.core.library.journeys.JourneyUris.JOURNEY_OPERATIONAL_PROFILE_REUSE_PATH;
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
    public static final String TEST_CRI_OAUTH_SESSION_ID = "test-cri-oauth-session-id";
    public static final String TEST_PREVIOUS_IPV_SESSION_ID = "previous-ipv-session-id";
    private static final List<VerifiableCredential> VCS_FROM_STORE =
            List.of(
                    vcWebPassportSuccessful(),
                    vcAddressM1a(),
                    vcExperianFraudM1a(),
                    vcExperianKbvM1a(),
                    vcDcmawDrivingPermitDvaM1b());
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
            new JourneyResponse(JOURNEY_F2F_PENDING_PATH);
    private static final JourneyResponse JOURNEY_F2F_FAIL =
            new JourneyResponse(JOURNEY_F2F_FAIL_PATH);
    private static final JourneyResponse JOURNEY_REPEAT_FRAUD_CHECK =
            new JourneyResponse(JOURNEY_REPEAT_FRAUD_CHECK_PATH);
    private static final JourneyResponse JOURNEY_DCMAW_ASYNC_VC_RECEIVED_LOW =
            new JourneyResponse(JOURNEY_DCMAW_ASYNC_VC_RECEIVED_LOW_PATH);
    private static final JourneyResponse JOURNEY_DCMAW_ASYNC_VC_RECEIVED_MEDIUM =
            new JourneyResponse(JOURNEY_DCMAW_ASYNC_VC_RECEIVED_MEDIUM_PATH);
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
    private static final VerifiableCredential gpg45Vc = vcWebDrivingPermitDvaValid();
    private static final VerifiableCredential f2fVc = vcF2fPassportPhotoM1a();
    private static ECDSASigner jwtSigner;
    private static VerifiableCredential pcl200Vc;
    private static VerifiableCredential pcl250Vc;
    private static AsyncCriStatus emptyAsyncCriStatus =
            new AsyncCriStatus(null, null, false, false, false);

    @Mock private Context context;
    @Mock private UserIdentityService userIdentityService;
    @Mock private CriResponseService criResponseService;
    @Mock private CriOAuthSessionService criOAuthSessionService;
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
    void setUpEach() throws ParseException {
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
        ipvSessionItem.setVot(Vot.P0);

        lenient()
                .when(mockVotMatcher.findStrongestMatches(any(), any(), any(), anyBoolean()))
                .thenReturn(new VotMatchingResult(Optional.empty(), Optional.empty(), null));

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
        when(criResponseService.getAsyncResponseStatus(eq(TEST_USER_ID), any(), eq(false)))
                .thenReturn(emptyAsyncCriStatus);

        JourneyResponse journeyResponse =
                toResponseClass(
                        checkExistingIdentityHandler.handleRequest(event, context),
                        JourneyResponse.class);

        assertEquals(JOURNEY_IPV_GPG45_MEDIUM, journeyResponse);

        verify(auditService, never()).sendAuditEvent(auditEventArgumentCaptor.capture());
    }

    @Test
    void shouldReturnJourneyNewGpg45LowIdentityForP1Vtr() throws Exception {
        when(ipvSessionService.getIpvSessionWithRetry(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        clientOAuthSessionItem.setVtr(List.of(P2.name(), P1.name()));
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(criResponseService.getAsyncResponseStatus(eq(TEST_USER_ID), any(), eq(false)))
                .thenReturn(emptyAsyncCriStatus);

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
        public void reuseSetup() throws Exception {
            when(ipvSessionService.getIpvSessionWithRetry(TEST_SESSION_ID))
                    .thenReturn(ipvSessionItem);
            when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                    .thenReturn(clientOAuthSessionItem);
        }

        @Test
        void shouldUseEvcsService() throws Exception {
            when(criResponseService.getAsyncResponseStatus(eq(TEST_USER_ID), any(), eq(false)))
                    .thenReturn(emptyAsyncCriStatus);
            when(mockEvcsService.fetchEvcsVerifiableCredentialsByState(
                            TEST_USER_ID, EVCS_TEST_TOKEN, CURRENT, PENDING_RETURN))
                    .thenReturn(Map.of(CURRENT, List.of(gpg45Vc)));

            checkExistingIdentityHandler.handleRequest(event, context);

            verify(clientOAuthSessionDetailsService).getClientOAuthSession(any());
            verify(mockEvcsService)
                    .fetchEvcsVerifiableCredentialsByState(
                            TEST_USER_ID, EVCS_TEST_TOKEN, CURRENT, PENDING_RETURN);
        }

        @ParameterizedTest
        @EnumSource(names = {"M1A", "M1B", "M2B"})
        void shouldReturnJourneyReuseResponseIfScoresSatisfyGpg45Profile(
                Gpg45Profile matchedProfile) throws Exception {
            var hmrcMigrationVC = vcHmrcMigrationPCL200();
            when(userIdentityService.areVcsCorrelated(any())).thenReturn(true);
            when(mockEvcsService.fetchEvcsVerifiableCredentialsByState(
                            TEST_USER_ID, EVCS_TEST_TOKEN, CURRENT, PENDING_RETURN))
                    .thenReturn(Map.of(CURRENT, List.of(gpg45Vc, hmrcMigrationVC)));
            when(criResponseService.getAsyncResponseStatus(eq(TEST_USER_ID), any(), eq(false)))
                    .thenReturn(emptyAsyncCriStatus);
            when(mockVotMatcher.findStrongestMatches(
                            List.of(P2), List.of(gpg45Vc, hmrcMigrationVC), List.of(), true))
                    .thenReturn(buildMatchResultFor(P2, matchedProfile));
            when(configService.enabled(RESET_IDENTITY)).thenReturn(false);

            var journeyResponse =
                    toResponseClass(
                            checkExistingIdentityHandler.handleRequest(event, context),
                            JourneyResponse.class);

            assertEquals(JOURNEY_REUSE, journeyResponse);

            verify(auditService, times(1)).sendAuditEvent(auditEventArgumentCaptor.capture());
            assertEquals(
                    AuditEventTypes.IPV_IDENTITY_REUSE_COMPLETE,
                    auditEventArgumentCaptor.getAllValues().get(0).getEventName());

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
            var vcs = List.of(gpg45Vc, vcF2fPassportPhotoM1a());
            when(mockEvcsService.fetchEvcsVerifiableCredentialsByState(
                            TEST_USER_ID, EVCS_TEST_TOKEN, CURRENT, PENDING_RETURN))
                    .thenReturn(Map.of(PENDING_RETURN, vcs));
            when(criResponseService.getCriResponseItems(TEST_USER_ID))
                    .thenReturn(
                            List.of(
                                    CriResponseItem.builder()
                                            .credentialIssuer(F2F.getId())
                                            .oauthState(TEST_CRI_OAUTH_SESSION_ID)
                                            .build()));
            when(criResponseService.getAsyncResponseStatus(TEST_USER_ID, vcs, true))
                    .thenReturn(emptyAsyncCriStatus);
            when(mockVotMatcher.findStrongestMatches(List.of(P2), vcs, List.of(), true))
                    .thenReturn(buildMatchResultFor(P2, M1A));
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
            var vcs = List.of(gpg45Vc, f2fVc);
            when(mockEvcsService.fetchEvcsVerifiableCredentialsByState(
                            TEST_USER_ID, EVCS_TEST_TOKEN, CURRENT, PENDING_RETURN))
                    .thenReturn(Map.of(PENDING_RETURN, vcs, CURRENT, List.of(inheritedIdentityVc)));
            var combinedVcs = List.of(inheritedIdentityVc, gpg45Vc, f2fVc);
            when(criResponseService.getCriResponseItems(TEST_USER_ID))
                    .thenReturn(
                            List.of(
                                    CriResponseItem.builder()
                                            .credentialIssuer(F2F.getId())
                                            .oauthState(TEST_CRI_OAUTH_SESSION_ID)
                                            .build()));
            when(criResponseService.getAsyncResponseStatus(TEST_USER_ID, combinedVcs, true))
                    .thenReturn(emptyAsyncCriStatus);

            checkExistingIdentityHandler.handleRequest(event, context);

            verify(userIdentityService).areVcsCorrelated(combinedVcs);
        }

        @Test // User returning after migration
        void shouldReturnJourneyOpProfileReuseResponseIfPCL200RequestedAndMetWhenNotInMigration()
                throws Exception {
            when(mockEvcsService.fetchEvcsVerifiableCredentialsByState(
                            TEST_USER_ID, EVCS_TEST_TOKEN, CURRENT, PENDING_RETURN))
                    .thenReturn(Map.of(CURRENT, List.of(gpg45Vc, pcl200Vc)));
            when(mockVotMatcher.findStrongestMatches(
                            List.of(P2, PCL250, PCL200),
                            List.of(gpg45Vc, pcl200Vc),
                            List.of(),
                            false))
                    .thenReturn(buildMatchResultFor(PCL200, null));
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
        }

        @Test // User returning after migration
        void shouldReturnJourneyOpProfileReuseResponseIfPCL250RequestedAndMetWhenNotInMigration()
                throws Exception {
            when(mockEvcsService.fetchEvcsVerifiableCredentialsByState(
                            TEST_USER_ID, EVCS_TEST_TOKEN, CURRENT, PENDING_RETURN))
                    .thenReturn(Map.of(CURRENT, List.of(gpg45Vc, pcl250Vc)));
            when(mockVotMatcher.findStrongestMatches(
                            List.of(P2, PCL250), List.of(gpg45Vc, pcl250Vc), List.of(), false))
                    .thenReturn(buildMatchResultFor(PCL250, null));
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
        }

        @Test // User returning after migration
        void shouldReturnJourneyOpProfileReuseResponseIfOpProfileAndPendingF2F() throws Exception {
            when(criResponseService.getAsyncResponseStatus(eq(TEST_USER_ID), any(), eq(false)))
                    .thenReturn(emptyAsyncCriStatus);
            when(mockEvcsService.fetchEvcsVerifiableCredentialsByState(
                            TEST_USER_ID, EVCS_TEST_TOKEN, CURRENT, PENDING_RETURN))
                    .thenReturn(Map.of(CURRENT, List.of(pcl250Vc)));
            when(mockVotMatcher.findStrongestMatches(
                            List.of(P2, PCL250), List.of(pcl250Vc), List.of(), false))
                    .thenReturn(buildMatchResultFor(PCL250, null));

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
        }

        @Test // User in process of migration
        void shouldReturnJourneyInMigrationReuseResponseIfPCL200RequestedAndMet() throws Exception {
            when(mockEvcsService.fetchEvcsVerifiableCredentialsByState(
                            TEST_USER_ID, EVCS_TEST_TOKEN, CURRENT, PENDING_RETURN))
                    .thenReturn(Map.of(CURRENT, List.of(gpg45Vc, pcl200Vc)));
            when(mockVotMatcher.findStrongestMatches(
                            List.of(P2, PCL250, PCL200),
                            List.of(gpg45Vc, pcl200Vc),
                            List.of(),
                            false))
                    .thenReturn(buildMatchResultFor(PCL200, null));
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
        }

        @Test // User in process of migration
        void shouldReturnJourneyInMigrationReuseResponseIfPCL250RequestedAndMet() throws Exception {
            when(mockEvcsService.fetchEvcsVerifiableCredentialsByState(
                            TEST_USER_ID, EVCS_TEST_TOKEN, CURRENT, PENDING_RETURN))
                    .thenReturn(Map.of(CURRENT, List.of(gpg45Vc, pcl250Vc)));
            when(mockVotMatcher.findStrongestMatches(
                            List.of(P2, PCL250), List.of(gpg45Vc, pcl250Vc), List.of(), true))
                    .thenReturn(buildMatchResultFor(PCL250, null));

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
        }

        @Test
        void shouldReturnErrorResponseIfVcCanNotBeStoredInSessionCredentialTable()
                throws Exception {
            when(mockVotMatcher.findStrongestMatches(List.of(P2), List.of(), List.of(), true))
                    .thenReturn(buildMatchResultFor(P2, M1A));
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
        when(mockEvcsService.fetchEvcsVerifiableCredentialsByState(
                        TEST_USER_ID, EVCS_TEST_TOKEN, CURRENT, PENDING_RETURN))
                .thenReturn(
                        Map.of(PENDING_RETURN, new ArrayList<>(List.of(vcF2fPassportPhotoM1a()))));
        when(criResponseService.getCriResponseItems(TEST_USER_ID))
                .thenReturn(
                        List.of(
                                CriResponseItem.builder()
                                        .credentialIssuer(F2F.getId())
                                        .oauthState(TEST_CRI_OAUTH_SESSION_ID)
                                        .build()));
        when(criResponseService.getAsyncResponseStatus(eq(TEST_USER_ID), any(), eq(true)))
                .thenReturn(
                        new AsyncCriStatus(F2F, AsyncCriStatus.STATUS_PENDING, false, true, false));
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

        assertEquals(Vot.P0, ipvSessionItem.getVot());
    }

    @ParameterizedTest
    @MethodSource("lowAndMediumConfidenceVtrs")
    void shouldReturnJourneyDcmawAsyncVcReceivedForDcmawAsyncComplete(
            List<String> vtr, JourneyResponse expectedJourney)
            throws IpvSessionNotFoundException,
                    HttpResponseExceptionWithErrorBody,
                    CredentialParseException,
                    VerifiableCredentialException,
                    EvcsServiceException {
        // Arrange
        when(ipvSessionService.getIpvSessionWithRetry(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(criResponseService.getCriResponseItem(TEST_USER_ID, DCMAW_ASYNC))
                .thenReturn(
                        CriResponseItem.builder().oauthState(TEST_CRI_OAUTH_SESSION_ID).build());
        when(criResponseService.getCriResponseItems(TEST_USER_ID))
                .thenReturn(
                        List.of(
                                CriResponseItem.builder()
                                        .credentialIssuer(DCMAW_ASYNC.getId())
                                        .oauthState(TEST_CRI_OAUTH_SESSION_ID)
                                        .build()));
        when(criOAuthSessionService.getCriOauthSessionItem(TEST_CRI_OAUTH_SESSION_ID))
                .thenReturn(
                        CriOAuthSessionItem.builder()
                                .clientOAuthSessionId(TEST_CLIENT_OAUTH_SESSION_ID)
                                .build());
        var previousIpvSession = new IpvSessionItem();
        previousIpvSession.setIpvSessionId(TEST_PREVIOUS_IPV_SESSION_ID);
        when(ipvSessionService.getIpvSessionByClientOAuthSessionId(TEST_CLIENT_OAUTH_SESSION_ID))
                .thenReturn(previousIpvSession);
        var vcs = List.of(vcDcmawAsyncDrivingPermitDva());
        when(criResponseService.getAsyncResponseStatus(eq(TEST_USER_ID), any(), eq(true)))
                .thenReturn(
                        new AsyncCriStatus(
                                DCMAW_ASYNC, AsyncCriStatus.STATUS_PENDING, false, true, false));
        Mockito.lenient().when(configService.enabled(P1_JOURNEYS_ENABLED)).thenReturn(true);
        when(mockEvcsService.fetchEvcsVerifiableCredentialsByState(
                        TEST_USER_ID, EVCS_TEST_TOKEN, CURRENT, PENDING_RETURN))
                .thenReturn(Map.of(PENDING_RETURN, vcs));
        when(userIdentityService.areVcsCorrelated(any())).thenReturn(true);

        clientOAuthSessionItem.setVtr(vtr);

        // Act
        JourneyResponse journeyResponse =
                toResponseClass(
                        checkExistingIdentityHandler.handleRequest(event, context),
                        JourneyResponse.class);

        // Assert
        assertEquals(expectedJourney, journeyResponse);
        verify(clientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());
        verify(mockSessionCredentialService).persistCredentials(vcs, TEST_SESSION_ID, true);
        verify(auditService).sendAuditEvent(auditEventArgumentCaptor.capture());
        assertEquals(
                AuditEventTypes.IPV_APP_SESSION_RECOVERED,
                auditEventArgumentCaptor.getValue().getEventName());
        assertEquals(
                TEST_PREVIOUS_IPV_SESSION_ID,
                ((AuditExtensionPreviousIpvSessionId)
                                auditEventArgumentCaptor.getValue().getExtensions())
                        .getPreviousIpvSessionId());
        assertEquals(Vot.P0, ipvSessionItem.getVot());
    }

    static Stream<Arguments> lowAndMediumConfidenceVtrs() {
        return Stream.of(
                Arguments.of(
                        List.of(Vot.P1.name(), Vot.P2.name()), JOURNEY_DCMAW_ASYNC_VC_RECEIVED_LOW),
                Arguments.of(List.of(Vot.P2.name()), JOURNEY_DCMAW_ASYNC_VC_RECEIVED_MEDIUM));
    }

    @Test
    void shouldReturnJourneyIpvGpg45MediumForDcmawAsyncCompleteAndVcIsExpired()
            throws IpvSessionNotFoundException,
                    HttpResponseExceptionWithErrorBody,
                    CredentialParseException,
                    EvcsServiceException {
        // Arrange
        when(ipvSessionService.getIpvSessionWithRetry(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(mockEvcsService.fetchEvcsVerifiableCredentialsByState(
                        TEST_USER_ID, EVCS_TEST_TOKEN, CURRENT, PENDING_RETURN))
                .thenReturn(Map.of(PENDING_RETURN, List.of(vcDcmawAsyncDrivingPermitDva())));
        when(criResponseService.getCriResponseItems(TEST_USER_ID))
                .thenReturn(
                        List.of(
                                CriResponseItem.builder()
                                        .credentialIssuer(DCMAW_ASYNC.getId())
                                        .oauthState(TEST_CRI_OAUTH_SESSION_ID)
                                        .build()));
        when(criResponseService.getAsyncResponseStatus(eq(TEST_USER_ID), any(), eq(true)))
                .thenReturn(emptyAsyncCriStatus);
        when(userIdentityService.areVcsCorrelated(any())).thenReturn(true);

        // Act
        JourneyResponse journeyResponse =
                toResponseClass(
                        checkExistingIdentityHandler.handleRequest(event, context),
                        JourneyResponse.class);

        // Assert
        assertEquals(JOURNEY_IPV_GPG45_MEDIUM, journeyResponse);

        verify(clientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());

        assertEquals(Vot.P0, ipvSessionItem.getVot());
    }

    @Test
    void shouldReturnNoMatchResponseIfVCsDoNotCorrelate() throws Exception {
        when(ipvSessionService.getIpvSessionWithRetry(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(mockEvcsService.fetchEvcsVerifiableCredentialsByState(
                        TEST_USER_ID, EVCS_TEST_TOKEN, CURRENT, PENDING_RETURN))
                .thenReturn(Map.of(CURRENT, List.of(vcF2fPassportPhotoM1a())));
        when(userIdentityService.areVcsCorrelated(any())).thenReturn(false);
        when(criResponseService.getAsyncResponseStatus(eq(TEST_USER_ID), any(), eq(false)))
                .thenReturn(emptyAsyncCriStatus);

        clientOAuthSessionItem.setVtr(List.of(Vot.PCL250.name(), PCL200.name(), P2.name()));

        JourneyResponse journeyResponse =
                toResponseClass(
                        checkExistingIdentityHandler.handleRequest(event, context),
                        JourneyResponse.class);

        assertEquals(JOURNEY_IPV_GPG45_MEDIUM, journeyResponse);

        verify(clientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());

        assertEquals(Vot.P0, ipvSessionItem.getVot());
    }

    @ParameterizedTest
    @MethodSource("votAndVtrCombinationsThatShouldStartIpvJourney")
    void shouldReturnJourneyIpvGpg45MediumResponseIfNoProfileAttainsVot(
            List<String> vtr, Optional<Vot> vot) throws Exception {
        when(ipvSessionService.getIpvSessionWithRetry(TEST_SESSION_ID)).thenReturn(ipvSessionItem);

        var credentials = new ArrayList<VerifiableCredential>();
        if (vot.isPresent()) {
            credentials.add(createOperationalProfileVc(vot.get()));
        }
        when(mockEvcsService.fetchEvcsVerifiableCredentialsByState(
                        TEST_USER_ID, EVCS_TEST_TOKEN, CURRENT, PENDING_RETURN))
                .thenReturn(Map.of(CURRENT, credentials));
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        clientOAuthSessionItem.setVtr(vtr);
        when(criResponseService.getAsyncResponseStatus(eq(TEST_USER_ID), any(), eq(false)))
                .thenReturn(emptyAsyncCriStatus);

        var journeyResponse =
                toResponseClass(
                        checkExistingIdentityHandler.handleRequest(event, context),
                        JourneyResponse.class);

        assertEquals(JOURNEY_IPV_GPG45_MEDIUM, journeyResponse);

        assertEquals(Vot.P0, ipvSessionItem.getVot());
    }

    @Test
    void shouldReturnJourneyIpvGpg45MediumResponseIfScoresDoNotSatisfyP2Gpg45Profile()
            throws Exception {
        when(ipvSessionService.getIpvSessionWithRetry(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(mockEvcsService.fetchEvcsVerifiableCredentialsByState(
                        TEST_USER_ID, EVCS_TEST_TOKEN, CURRENT, PENDING_RETURN))
                .thenReturn(Map.of(CURRENT, VCS_FROM_STORE));
        when(criResponseService.getAsyncResponseStatus(eq(TEST_USER_ID), any(), eq(false)))
                .thenReturn(emptyAsyncCriStatus);
        when(userIdentityService.areVcsCorrelated(any())).thenReturn(true);
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        var journeyResponse =
                toResponseClass(
                        checkExistingIdentityHandler.handleRequest(event, context),
                        JourneyResponse.class);

        assertEquals(JOURNEY_IPV_GPG45_MEDIUM, journeyResponse);

        verify(clientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());

        assertEquals(Vot.P0, ipvSessionItem.getVot());
    }

    @Test
    void shouldNotSendAuditEventIfNewUser() throws Exception {
        when(ipvSessionService.getIpvSessionWithRetry(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(criResponseService.getAsyncResponseStatus(eq(TEST_USER_ID), any(), eq(false)))
                .thenReturn(emptyAsyncCriStatus);
        when(userIdentityService.areVcsCorrelated(any())).thenReturn(true);
        when(mockEvcsService.fetchEvcsVerifiableCredentialsByState(
                        TEST_USER_ID, EVCS_TEST_TOKEN, CURRENT, PENDING_RETURN))
                .thenReturn(Map.of());
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        var journeyResponse =
                toResponseClass(
                        checkExistingIdentityHandler.handleRequest(event, context),
                        JourneyResponse.class);

        assertEquals(JOURNEY_IPV_GPG45_MEDIUM_PATH, journeyResponse.getJourney());

        verify(auditService, never()).sendAuditEvent(auditEventArgumentCaptor.capture());
        verify(clientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());

        assertEquals(Vot.P0, ipvSessionItem.getVot());
    }

    @Test
    void shouldReturn400IfSessionIdNotInHeader() throws Exception {
        var eventWithoutHeaders = JourneyRequest.builder().build();

        var journeyResponse =
                toResponseClass(
                        checkExistingIdentityHandler.handleRequest(eventWithoutHeaders, context),
                        JourneyErrorResponse.class);

        assertEquals(JOURNEY_ERROR_PATH, journeyResponse.getJourney());

        assertEquals(HttpStatusCode.BAD_REQUEST, journeyResponse.getStatusCode());
        assertEquals(ErrorResponse.MISSING_IPV_SESSION_ID.getCode(), journeyResponse.getCode());
        assertEquals(
                ErrorResponse.MISSING_IPV_SESSION_ID.getMessage(), journeyResponse.getMessage());
        verify(clientOAuthSessionDetailsService, times(0)).getClientOAuthSession(any());

        verify(ipvSessionService, never()).updateIpvSession(any());

        assertEquals(Vot.P0, ipvSessionItem.getVot());
    }

    @Test
    void shouldReturnPendingResponseIfFaceToFaceVerificationIsPending() throws Exception {
        when(ipvSessionService.getIpvSessionWithRetry(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(criResponseService.getAsyncResponseStatus(eq(TEST_USER_ID), any(), eq(false)))
                .thenReturn(
                        new AsyncCriStatus(F2F, AsyncCriStatus.STATUS_PENDING, true, false, false));
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        var journeyResponse =
                toResponseClass(
                        checkExistingIdentityHandler.handleRequest(event, context),
                        JourneyResponse.class);

        assertEquals(JOURNEY_PENDING, journeyResponse);

        assertEquals(Vot.P0, ipvSessionItem.getVot());
    }

    @Test
    void shouldReturnPendingResponseIfFaceToFaceVerificationIsPendingAndBreachingCi()
            throws Exception {
        when(ipvSessionService.getIpvSessionWithRetry(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(criResponseService.getAsyncResponseStatus(eq(TEST_USER_ID), any(), eq(false)))
                .thenReturn(
                        new AsyncCriStatus(F2F, AsyncCriStatus.STATUS_PENDING, true, false, false));
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(cimitUtilityService.isBreachingCiThreshold(any(), any())).thenReturn(true);
        when(cimitUtilityService.getCiMitigationEvent(any(), any()))
                .thenReturn(Optional.of(ENHANCED_VERIFICATION_EVENT));

        var journeyResponse =
                toResponseClass(
                        checkExistingIdentityHandler.handleRequest(event, context),
                        JourneyResponse.class);

        assertEquals(JOURNEY_PENDING, journeyResponse);

        assertEquals(Vot.P0, ipvSessionItem.getVot());
    }

    @Test
    void shouldReturnFailResponseIfFaceToFaceVerificationIsError() throws Exception {
        when(ipvSessionService.getIpvSessionWithRetry(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(criResponseService.getAsyncResponseStatus(eq(TEST_USER_ID), any(), eq(false)))
                .thenReturn(
                        new AsyncCriStatus(F2F, AsyncCriStatus.STATUS_ERROR, true, false, false));
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        var journeyResponse =
                toResponseClass(
                        checkExistingIdentityHandler.handleRequest(event, context),
                        JourneyResponse.class);

        assertEquals(JOURNEY_F2F_FAIL, journeyResponse);

        assertEquals(Vot.P0, ipvSessionItem.getVot());
    }

    @Test
    void shouldReturnFailResponseIfFaceToFaceVerificationIsAbandon() throws Exception {
        when(ipvSessionService.getIpvSessionWithRetry(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(criResponseService.getAsyncResponseStatus(eq(TEST_USER_ID), any(), eq(false)))
                .thenReturn(
                        new AsyncCriStatus(F2F, AsyncCriStatus.STATUS_ABANDON, true, false, false));
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        var journeyResponse =
                toResponseClass(
                        checkExistingIdentityHandler.handleRequest(event, context),
                        JourneyResponse.class);

        assertEquals(JOURNEY_F2F_FAIL, journeyResponse);

        assertEquals(Vot.P0, ipvSessionItem.getVot());
    }

    @Test
    void shouldReturnFailResponseForFaceToFaceVerificationIfNoMatchedProfile() throws Exception {
        when(ipvSessionService.getIpvSessionWithRetry(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(mockEvcsService.fetchEvcsVerifiableCredentialsByState(
                        TEST_USER_ID, EVCS_TEST_TOKEN, CURRENT, PENDING_RETURN))
                .thenReturn(
                        Map.of(PENDING_RETURN, new ArrayList<>(List.of(vcF2fPassportPhotoM1a()))));
        when(criResponseService.getCriResponseItems(TEST_USER_ID))
                .thenReturn(
                        List.of(
                                CriResponseItem.builder()
                                        .credentialIssuer(F2F.getId())
                                        .oauthState(TEST_CRI_OAUTH_SESSION_ID)
                                        .build()));
        when(criResponseService.getAsyncResponseStatus(eq(TEST_USER_ID), any(), eq(true)))
                .thenReturn(
                        new AsyncCriStatus(F2F, AsyncCriStatus.STATUS_PENDING, false, true, false));
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

        assertEquals(Vot.P0, ipvSessionItem.getVot());
    }

    @Test
    void shouldReturnFailResponseForFaceToFaceIfVCsDoNotCorrelate() throws Exception {
        when(ipvSessionService.getIpvSessionWithRetry(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(mockEvcsService.fetchEvcsVerifiableCredentialsByState(
                        TEST_USER_ID, EVCS_TEST_TOKEN, CURRENT, PENDING_RETURN))
                .thenReturn(
                        Map.of(PENDING_RETURN, new ArrayList<>(List.of(vcF2fPassportPhotoM1a()))));
        when(criResponseService.getCriResponseItems(TEST_USER_ID))
                .thenReturn(
                        List.of(
                                CriResponseItem.builder()
                                        .credentialIssuer(F2F.getId())
                                        .oauthState(TEST_CRI_OAUTH_SESSION_ID)
                                        .build()));
        when(criResponseService.getAsyncResponseStatus(eq(TEST_USER_ID), any(), eq(true)))
                .thenReturn(
                        new AsyncCriStatus(F2F, AsyncCriStatus.STATUS_PENDING, false, true, false));
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

        assertEquals(Vot.P0, ipvSessionItem.getVot());
    }

    @Test
    void shouldReturnJourneyIpvGpg45MediumIfDataDoesNotCorrelateAndNotF2F() throws Exception {
        when(ipvSessionService.getIpvSessionWithRetry(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(mockEvcsService.fetchEvcsVerifiableCredentialsByState(
                        TEST_USER_ID, EVCS_TEST_TOKEN, CURRENT, PENDING_RETURN))
                .thenReturn(
                        Map.of(PENDING_RETURN, new ArrayList<>(List.of(vcF2fPassportPhotoM1a()))));
        when(criResponseService.getCriResponseItems(TEST_USER_ID))
                .thenReturn(
                        List.of(
                                CriResponseItem.builder()
                                        .credentialIssuer(F2F.getId())
                                        .oauthState(TEST_CRI_OAUTH_SESSION_ID)
                                        .build()));
        when(criResponseService.getAsyncResponseStatus(eq(TEST_USER_ID), any(), eq(true)))
                .thenReturn(emptyAsyncCriStatus);
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        var journeyResponse =
                toResponseClass(
                        checkExistingIdentityHandler.handleRequest(event, context),
                        JourneyResponse.class);

        assertEquals(JOURNEY_IPV_GPG45_MEDIUM, journeyResponse);

        assertEquals(Vot.P0, ipvSessionItem.getVot());
    }

    @Test
    void shouldReturnFailWithCiJourneyResponseForCiBreachAndNoMitigationsAvailable()
            throws Exception {
        when(ipvSessionService.getIpvSessionWithRetry(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(cimitUtilityService.getContraIndicatorsFromVc(any())).thenReturn(List.of());
        when(cimitUtilityService.isBreachingCiThreshold(any(), any())).thenReturn(true);
        when(cimitUtilityService.getCiMitigationEvent(any(), any())).thenReturn(Optional.empty());
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(criResponseService.getAsyncResponseStatus(eq(TEST_USER_ID), any(), eq(false)))
                .thenReturn(emptyAsyncCriStatus);

        var response =
                toResponseClass(
                        checkExistingIdentityHandler.handleRequest(event, context),
                        JourneyResponse.class);

        assertEquals(JOURNEY_FAIL_WITH_CI_PATH, response.getJourney());
    }

    @Test
    void shouldReturnNewIdentityJourneyWhenCiIsBreachingButMitigationIsAvailable()
            throws Exception {
        when(ipvSessionService.getIpvSessionWithRetry(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(cimitUtilityService.getContraIndicatorsFromVc(any())).thenReturn(List.of());
        when(cimitUtilityService.isBreachingCiThreshold(any(), any())).thenReturn(true);
        when(cimitUtilityService.getCiMitigationEvent(any(), any()))
                .thenReturn(Optional.of(ENHANCED_VERIFICATION_EVENT));
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(criResponseService.getAsyncResponseStatus(eq(TEST_USER_ID), any(), eq(false)))
                .thenReturn(emptyAsyncCriStatus);

        var response =
                toResponseClass(
                        checkExistingIdentityHandler.handleRequest(event, context),
                        JourneyResponse.class);

        assertEquals(JOURNEY_IPV_GPG45_MEDIUM_PATH, response.getJourney());
    }

    private static Stream<Arguments> f2fIncompleteStatus() {
        return Stream.of(
                Arguments.of(AsyncCriStatus.STATUS_PENDING, JOURNEY_F2F_PENDING_PATH),
                Arguments.of(AsyncCriStatus.STATUS_ABANDON, JOURNEY_F2F_FAIL_PATH),
                Arguments.of(AsyncCriStatus.STATUS_ERROR, JOURNEY_F2F_FAIL_PATH));
    }

    @ParameterizedTest
    @MethodSource("f2fIncompleteStatus")
    void shouldReturnF2fJourneyResponseWhenCiIsBreachingButMitigationIsAvailable(
            String asyncCriStatus, String expectedJourney) throws Exception {
        when(ipvSessionService.getIpvSessionWithRetry(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(cimitUtilityService.getContraIndicatorsFromVc(any())).thenReturn(List.of());
        when(cimitUtilityService.isBreachingCiThreshold(any(), any())).thenReturn(true);
        when(cimitUtilityService.getCiMitigationEvent(any(), any()))
                .thenReturn(Optional.of(ENHANCED_VERIFICATION_EVENT));
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(criResponseService.getAsyncResponseStatus(TEST_USER_ID, List.of(), false))
                .thenReturn(new AsyncCriStatus(F2F, asyncCriStatus, true, true, false));

        var response =
                toResponseClass(
                        checkExistingIdentityHandler.handleRequest(event, context),
                        JourneyResponse.class);

        assertEquals(expectedJourney, response.getJourney());
    }

    @Test
    void shouldReturn500IfFailedToRetrieveCisFromStorageSystem() throws Exception {
        when(ipvSessionService.getIpvSessionWithRetry(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(cimitService.fetchContraIndicatorsVc(anyString(), anyString(), anyString(), any()))
                .thenThrow(CiRetrievalException.class);
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(mockEvcsService.fetchEvcsVerifiableCredentialsByState(
                        TEST_USER_ID, EVCS_TEST_TOKEN, CURRENT, PENDING_RETURN))
                .thenReturn(Map.of());

        var response =
                toResponseClass(
                        checkExistingIdentityHandler.handleRequest(event, context),
                        JourneyErrorResponse.class);

        assertEquals(HttpStatusCode.INTERNAL_SERVER_ERROR, response.getStatusCode());
        assertEquals(ErrorResponse.FAILED_TO_GET_STORED_CIS.getCode(), response.getCode());
        assertEquals(ErrorResponse.FAILED_TO_GET_STORED_CIS.getMessage(), response.getMessage());
        verify(clientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());
    }

    @Test
    void shouldReturn500IfFailedToGetCisFromCiVc() throws Exception {
        when(ipvSessionService.getIpvSessionWithRetry(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(cimitUtilityService.getContraIndicatorsFromVc(any()))
                .thenThrow(CiExtractionException.class);
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(mockEvcsService.fetchEvcsVerifiableCredentialsByState(
                        TEST_USER_ID, EVCS_TEST_TOKEN, CURRENT, PENDING_RETURN))
                .thenReturn(Map.of());

        var response =
                toResponseClass(
                        checkExistingIdentityHandler.handleRequest(event, context),
                        JourneyErrorResponse.class);

        assertEquals(HttpStatusCode.INTERNAL_SERVER_ERROR, response.getStatusCode());
        assertEquals(ErrorResponse.FAILED_TO_EXTRACT_CIS_FROM_VC.getCode(), response.getCode());
        assertEquals(
                ErrorResponse.FAILED_TO_EXTRACT_CIS_FROM_VC.getMessage(), response.getMessage());
        verify(clientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());
    }

    @Test
    void shouldReturn500IfUnableToParseCredentials() throws Exception {
        when(ipvSessionService.getIpvSessionWithRetry(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(mockEvcsService.fetchEvcsVerifiableCredentialsByState(
                        TEST_USER_ID, EVCS_TEST_TOKEN, CURRENT, PENDING_RETURN))
                .thenThrow(CredentialParseException.class);

        var response =
                toResponseClass(
                        checkExistingIdentityHandler.handleRequest(event, context),
                        JourneyErrorResponse.class);

        assertEquals(HttpStatusCode.INTERNAL_SERVER_ERROR, response.getStatusCode());
        assertEquals(
                ErrorResponse.FAILED_TO_PARSE_SUCCESSFUL_VC_STORE_ITEMS.getCode(),
                response.getCode());
        assertEquals(
                ErrorResponse.FAILED_TO_PARSE_SUCCESSFUL_VC_STORE_ITEMS.getMessage(),
                response.getMessage());
        verify(clientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());
    }

    @Test
    void shouldReturn500IfFailedToGetCimitConfig() throws Exception {
        when(ipvSessionService.getIpvSessionWithRetry(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(cimitUtilityService.isBreachingCiThreshold(any(), any())).thenReturn(Boolean.TRUE);
        when(cimitUtilityService.getCiMitigationEvent(any(), any()))
                .thenThrow(new ConfigException("Failed to get cimit config"));

        var response =
                toResponseClass(
                        checkExistingIdentityHandler.handleRequest(event, context),
                        JourneyErrorResponse.class);

        assertEquals(HttpStatusCode.INTERNAL_SERVER_ERROR, response.getStatusCode());
        assertEquals(ErrorResponse.FAILED_TO_PARSE_CONFIG.getCode(), response.getCode());
        assertEquals(ErrorResponse.FAILED_TO_PARSE_CONFIG.getMessage(), response.getMessage());
        verify(clientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());
    }

    @Test
    void shouldReturn500IfUnrecognisedCiReceived() throws Exception {
        when(ipvSessionService.getIpvSessionWithRetry(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(cimitService.fetchContraIndicatorsVc(
                        TEST_USER_ID, TEST_JOURNEY_ID, TEST_CLIENT_SOURCE_IP, ipvSessionItem))
                .thenThrow(new UnrecognisedCiException("Unrecognised CI"));

        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        var response =
                toResponseClass(
                        checkExistingIdentityHandler.handleRequest(event, context),
                        JourneyErrorResponse.class);

        assertEquals(JourneyUris.JOURNEY_ERROR_PATH, response.getJourney());
        assertEquals(HttpStatusCode.INTERNAL_SERVER_ERROR, response.getStatusCode());
        assertEquals(ErrorResponse.UNRECOGNISED_CI_CODE.getCode(), response.getCode());
        assertEquals(ErrorResponse.UNRECOGNISED_CI_CODE.getMessage(), response.getMessage());
    }

    @Nested
    class ReproveIdentity {
        @BeforeEach
        public void beforeEach() throws Exception {
            when(ipvSessionService.getIpvSessionWithRetry(TEST_SESSION_ID))
                    .thenReturn(ipvSessionItem);
            when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                    .thenReturn(clientOAuthSessionItem);
        }

        @Test
        void shouldReturnReproveP2JourneyIfReproveIdentityFlagSet() {
            clientOAuthSessionItem.setReproveIdentity(Boolean.TRUE);
            when(criResponseService.getAsyncResponseStatus(TEST_USER_ID, List.of(), false))
                    .thenReturn(emptyAsyncCriStatus);

            var journeyResponse =
                    toResponseClass(
                            checkExistingIdentityHandler.handleRequest(event, context),
                            JourneyResponse.class);

            assertEquals(JOURNEY_REPROVE_IDENTITY_GPG45_MEDIUM_PATH, journeyResponse.getJourney());
        }

        @Test
        void shouldReturnReproveP1JourneyIfReproveIdentityFlagSet() {
            clientOAuthSessionItem.setReproveIdentity(Boolean.TRUE);
            clientOAuthSessionItem.setVtr(List.of(P2.name(), P1.name()));
            lenient().when(configService.enabled(P1_JOURNEYS_ENABLED)).thenReturn(true);
            when(criResponseService.getAsyncResponseStatus(eq(TEST_USER_ID), any(), eq(false)))
                    .thenReturn(emptyAsyncCriStatus);

            var journeyResponse =
                    toResponseClass(
                            checkExistingIdentityHandler.handleRequest(event, context),
                            JourneyResponse.class);

            assertEquals(JOURNEY_REPROVE_IDENTITY_GPG45_LOW_PATH, journeyResponse.getJourney());
        }

        @Test
        void shouldReturnReproveP2JourneyIfReproveIdentityFlagSetAndPendingF2FDoesNotHaveFlag() {
            clientOAuthSessionItem.setReproveIdentity(Boolean.TRUE);
            when(criResponseService.getAsyncResponseStatus(TEST_USER_ID, List.of(), false))
                    .thenReturn(
                            new AsyncCriStatus(
                                    F2F, AsyncCriStatus.STATUS_PENDING, false, false, false));

            var journeyResponse =
                    toResponseClass(
                            checkExistingIdentityHandler.handleRequest(event, context),
                            JourneyResponse.class);

            assertEquals(JOURNEY_REPROVE_IDENTITY_GPG45_MEDIUM_PATH, journeyResponse.getJourney());
        }

        @Test
        void shouldReturnReproveP2JourneyIfReproveIdentityFlagSetAndIdentityIsNotPending()
                throws Exception {
            clientOAuthSessionItem.setReproveIdentity(Boolean.TRUE);
            var vcs = new ArrayList<>(List.of(gpg45Vc, f2fVc));
            when(mockEvcsService.fetchEvcsVerifiableCredentialsByState(
                            TEST_USER_ID, EVCS_TEST_TOKEN, CURRENT, PENDING_RETURN))
                    .thenReturn(Map.of(CURRENT, vcs));
            when(criResponseService.getAsyncResponseStatus(TEST_USER_ID, vcs, false))
                    .thenReturn(
                            new AsyncCriStatus(
                                    F2F, AsyncCriStatus.STATUS_PENDING, false, true, true));

            var journeyResponse =
                    toResponseClass(
                            checkExistingIdentityHandler.handleRequest(event, context),
                            JourneyResponse.class);

            assertEquals(JOURNEY_REPROVE_IDENTITY_GPG45_MEDIUM_PATH, journeyResponse.getJourney());
        }

        @Test
        void shouldNotReturnReproveJourneyIfUserHasPendingF2FWithReproveFlag() throws Exception {
            clientOAuthSessionItem.setReproveIdentity(Boolean.TRUE);
            var vcs = new ArrayList<>(List.of(f2fVc));
            when(mockEvcsService.fetchEvcsVerifiableCredentialsByState(
                            TEST_USER_ID, EVCS_TEST_TOKEN, CURRENT, PENDING_RETURN))
                    .thenReturn(Map.of(PENDING_RETURN, vcs));
            when(criResponseService.getCriResponseItems(TEST_USER_ID))
                    .thenReturn(
                            List.of(
                                    CriResponseItem.builder()
                                            .credentialIssuer(F2F.getId())
                                            .oauthState(TEST_CRI_OAUTH_SESSION_ID)
                                            .build()));
            when(criResponseService.getAsyncResponseStatus(TEST_USER_ID, vcs, true))
                    .thenReturn(
                            new AsyncCriStatus(
                                    F2F, AsyncCriStatus.STATUS_PENDING, true, true, true));

            var journeyResponse =
                    toResponseClass(
                            checkExistingIdentityHandler.handleRequest(event, context),
                            JourneyResponse.class);

            assertEquals(JOURNEY_F2F_PENDING_PATH, journeyResponse.getJourney());

            verify(criResponseService, never()).updateCriResponseItem(any());
        }

        @Test
        void shouldReturnReproveP2JourneyStepResponseIfResetIdentityTrue() throws Exception {
            when(cimitUtilityService.getContraIndicatorsFromVc(any())).thenReturn(List.of());
            when(configService.enabled(RESET_IDENTITY)).thenReturn(true);

            var journeyResponse =
                    toResponseClass(
                            checkExistingIdentityHandler.handleRequest(event, context),
                            JourneyResponse.class);

            assertEquals(JOURNEY_REPROVE_IDENTITY_GPG45_MEDIUM_PATH, journeyResponse.getJourney());
        }

        @Test
        void shouldReturnReproveP1JourneyStepResponseIfResetIdentityTrueAndP1InVtr()
                throws Exception {
            clientOAuthSessionItem.setVtr(List.of(P2.name(), P1.name()));
            when(cimitUtilityService.getContraIndicatorsFromVc(any())).thenReturn(List.of());
            when(configService.enabled(RESET_IDENTITY)).thenReturn(true);

            var journeyResponse =
                    toResponseClass(
                            checkExistingIdentityHandler.handleRequest(event, context),
                            JourneyResponse.class);

            assertEquals(JOURNEY_REPROVE_IDENTITY_GPG45_LOW_PATH, journeyResponse.getJourney());
        }
    }

    @Test
    void shouldReturnNewIdentityJourneyIfNotBreachingCiThreshold() throws Exception {
        var mitigatedCI = new ContraIndicator();
        mitigatedCI.setCode("test_code");
        mitigatedCI.setMitigation(List.of(new Mitigation()));
        var testContraIndicators = List.of(mitigatedCI);

        when(ipvSessionService.getIpvSessionWithRetry(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(mockEvcsService.fetchEvcsVerifiableCredentialsByState(
                        TEST_USER_ID, EVCS_TEST_TOKEN, CURRENT, PENDING_RETURN))
                .thenReturn(Map.of());
        when(cimitUtilityService.getContraIndicatorsFromVc(any())).thenReturn(testContraIndicators);
        when(criResponseService.getAsyncResponseStatus(eq(TEST_USER_ID), any(), eq(false)))
                .thenReturn(emptyAsyncCriStatus);
        when(cimitUtilityService.isBreachingCiThreshold(any(), any())).thenReturn(false);

        var journeyResponse =
                toResponseClass(
                        checkExistingIdentityHandler.handleRequest(event, context),
                        JourneyResponse.class);

        assertEquals(JOURNEY_IPV_GPG45_MEDIUM_PATH, journeyResponse.getJourney());
    }

    @Test
    void shouldReturnF2fFailJourneyResponseWhenFailedToMatchF2fProfile() throws Exception {
        var mitigatedCI = new ContraIndicator();
        mitigatedCI.setCode("test_code");
        mitigatedCI.setMitigation(List.of(new Mitigation()));
        var testContraIndicators = List.of(mitigatedCI);

        when(ipvSessionService.getIpvSessionWithRetry(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(mockEvcsService.fetchEvcsVerifiableCredentialsByState(
                        TEST_USER_ID, EVCS_TEST_TOKEN, CURRENT, PENDING_RETURN))
                .thenReturn(
                        Map.of(PENDING_RETURN, new ArrayList<>(List.of(vcF2fPassportPhotoM1a()))));
        when(criResponseService.getCriResponseItems(TEST_USER_ID))
                .thenReturn(
                        List.of(
                                CriResponseItem.builder()
                                        .credentialIssuer(F2F.getId())
                                        .oauthState(TEST_CRI_OAUTH_SESSION_ID)
                                        .build()));
        when(criResponseService.getAsyncResponseStatus(eq(TEST_USER_ID), any(), eq(true)))
                .thenReturn(
                        new AsyncCriStatus(F2F, AsyncCriStatus.STATUS_PENDING, false, true, false));
        when(cimitUtilityService.getContraIndicatorsFromVc(any())).thenReturn(testContraIndicators);
        when(cimitUtilityService.isBreachingCiThreshold(any(), any())).thenReturn(false);

        var journeyResponse =
                toResponseClass(
                        checkExistingIdentityHandler.handleRequest(event, context),
                        JourneyResponse.class);

        assertEquals(JOURNEY_F2F_FAIL_PATH, journeyResponse.getJourney());
    }

    @Test
    void shouldReturnNewIdentityJourneyWhenPendingReturnVcNotAssociatedWithPendingRecord()
            throws Exception {
        // Arrange
        when(ipvSessionService.getIpvSessionWithRetry(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(clientOAuthSessionDetailsService.getClientOAuthSession(TEST_CLIENT_OAUTH_SESSION_ID))
                .thenReturn(clientOAuthSessionItem);
        when(mockEvcsService.fetchEvcsVerifiableCredentialsByState(
                        TEST_USER_ID, EVCS_TEST_TOKEN, CURRENT, PENDING_RETURN))
                .thenReturn(Map.of(PENDING_RETURN, new ArrayList<>(List.of(f2fVc))));
        when(criResponseService.getCriResponseItems(TEST_USER_ID)).thenReturn(List.of());
        when(criResponseService.getAsyncResponseStatus(TEST_USER_ID, List.of(), false))
                .thenReturn(
                        new AsyncCriStatus(
                                F2F, AsyncCriStatus.STATUS_PENDING, false, false, false));
        when(cimitUtilityService.isBreachingCiThreshold(List.of(), P2)).thenReturn(false);

        // Act
        var journeyResponse =
                toResponseClass(
                        checkExistingIdentityHandler.handleRequest(event, context),
                        JourneyResponse.class);

        // Assert
        assertEquals(JOURNEY_IPV_GPG45_MEDIUM_PATH, journeyResponse.getJourney());
    }

    @Test
    void shouldReturnJourneyRepeatFraudCheckResponseIfExpiredFraudAndFlagIsTrue() throws Exception {
        when(ipvSessionService.getIpvSessionWithRetry(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        var fraudVc = vcExperianFraudM1aExpired();
        var vcs =
                List.of(
                        vcWebPassportSuccessful(),
                        vcAddressM1a(),
                        fraudVc,
                        vcExperianKbvM1a(),
                        vcDcmawDrivingPermitDvaM1b());
        when(mockEvcsService.fetchEvcsVerifiableCredentialsByState(
                        TEST_USER_ID, EVCS_TEST_TOKEN, CURRENT, PENDING_RETURN))
                .thenReturn(Map.of(CURRENT, vcs));

        when(mockVotMatcher.findStrongestMatches(List.of(P2), vcs, List.of(), true))
                .thenReturn(buildMatchResultFor(P2, M1B));
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

        var expectedStoredVc = vcs.stream().filter(vc -> vc != fraudVc).toList();
        verify(mockSessionCredentialService)
                .persistCredentials(expectedStoredVc, ipvSessionItem.getIpvSessionId(), false);

        assertEquals(Vot.P0, ipvSessionItem.getVot());
    }

    @Test
    void shouldNotReturnJourneyRepeatFraudCheckResponseIfNotExpiredFraudAndFlagIsTrue()
            throws Exception {
        when(ipvSessionService.getIpvSessionWithRetry(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(mockEvcsService.fetchEvcsVerifiableCredentialsByState(
                        TEST_USER_ID, EVCS_TEST_TOKEN, CURRENT, PENDING_RETURN))
                .thenReturn(Map.of(CURRENT, VCS_FROM_STORE));

        when(mockVotMatcher.findStrongestMatches(List.of(P2), VCS_FROM_STORE, List.of(), true))
                .thenReturn(buildMatchResultFor(P2, M1B));

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

    private static VerifiableCredential createOperationalProfileVc(Vot vot) throws Exception {
        var testVcClaim = vcClaimDcmawPassport();
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

    private static VotMatchingResult buildMatchResultFor(Vot vot, Gpg45Profile profile) {
        return new VotMatchingResult(
                Optional.of(
                        new VotMatchingResult.VotAndProfile(
                                vot, profile == null ? Optional.empty() : Optional.of(profile))),
                Optional.of(
                        new VotMatchingResult.VotAndProfile(
                                vot, profile == null ? Optional.empty() : Optional.of(profile))),
                Gpg45Scores.builder().build());
    }
}
