package uk.gov.di.ipv.core.evaluategpg45scores;

import com.amazonaws.services.lambda.runtime.Context;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.AfterEach;
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
import software.amazon.awssdk.http.HttpStatusCode;
import uk.gov.di.ipv.core.library.auditing.AuditEvent;
import uk.gov.di.ipv.core.library.auditing.AuditEventTypes;
import uk.gov.di.ipv.core.library.auditing.AuditEventUser;
import uk.gov.di.ipv.core.library.auditing.extension.AuditExtensionGpg45ProfileMatched;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.domain.JourneyErrorResponse;
import uk.gov.di.ipv.core.library.domain.JourneyRequest;
import uk.gov.di.ipv.core.library.domain.JourneyResponse;
import uk.gov.di.ipv.core.library.enums.Vot;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;
import uk.gov.di.ipv.core.library.exceptions.IpvSessionNotFoundException;
import uk.gov.di.ipv.core.library.exceptions.VerifiableCredentialException;
import uk.gov.di.ipv.core.library.gpg45.Gpg45ProfileEvaluator;
import uk.gov.di.ipv.core.library.gpg45.Gpg45Scores;
import uk.gov.di.ipv.core.library.gpg45.enums.Gpg45Profile;
import uk.gov.di.ipv.core.library.helpers.SecureTokenHelper;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.CimitUtilityService;
import uk.gov.di.ipv.core.library.service.ClientOAuthSessionDetailsService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.IpvSessionService;
import uk.gov.di.ipv.core.library.service.UserIdentityService;
import uk.gov.di.ipv.core.library.testhelpers.unit.LogCollector;
import uk.gov.di.ipv.core.library.verifiablecredential.service.SessionCredentialsService;
import uk.gov.di.model.ContraIndicator;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import static com.nimbusds.oauth2.sdk.http.HTTPResponse.SC_SERVER_ERROR;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.core.StringContains.containsString;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.domain.ErrorResponse.FAILED_TO_PARSE_ISSUED_CREDENTIALS;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.DCMAW_PASSPORT_VC;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.M1A_ADDRESS_VC;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.M1A_EXPERIAN_FRAUD_VC;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.PASSPORT_NON_DCMAW_SUCCESSFUL_VC;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcExperianFraudScoreOne;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcFraudApplicableAuthoritativeSourceFailed;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcVerificationM1a;
import static uk.gov.di.ipv.core.library.gpg45.enums.Gpg45Profile.L1A;
import static uk.gov.di.ipv.core.library.gpg45.enums.Gpg45Profile.M1A;
import static uk.gov.di.ipv.core.library.gpg45.enums.Gpg45Profile.M1B;
import static uk.gov.di.ipv.core.library.gpg45.enums.Gpg45Profile.M1C;
import static uk.gov.di.ipv.core.library.gpg45.enums.Gpg45Profile.M2B;

@ExtendWith(MockitoExtension.class)
class EvaluateGpg45ScoresHandlerTest {
    private static final String TEST_SESSION_ID = "test-session-id";
    private static final String TEST_USER_ID = "test-user-id";
    private static final String TEST_JOURNEY_ID = "test-journey-id";
    private static JourneyRequest request;
    private static final String TEST_CLIENT_SOURCE_IP = "test-client-source-ip";
    private static final List<Gpg45Profile> P2_PROFILES = List.of(M1A, M1B, M2B);
    private static final List<Gpg45Profile> P2_PROFILES_PLUS_M1C = List.of(M1A, M1B, M2B, M1C);
    private static final List<Gpg45Profile> P1_PROFILES = List.of(L1A);
    private static final List<ContraIndicator> CONTRAINDICATORS = List.of();
    private static final JourneyResponse JOURNEY_MET = new JourneyResponse("/journey/met");
    private static final JourneyResponse JOURNEY_UNMET = new JourneyResponse("/journey/unmet");
    private static final JourneyResponse JOURNEY_ERROR = new JourneyResponse("/journey/error");
    private static final String JOURNEY_VCS_NOT_CORRELATED = "/journey/vcs-not-correlated";
    private static final String TEST_CLIENT_OAUTH_SESSION_ID =
            SecureTokenHelper.getInstance().generate();
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    @Mock private Context context;
    @Mock private ConfigService configService;
    @Mock private UserIdentityService userIdentityService;
    @Mock private IpvSessionService ipvSessionService;
    @Mock private Gpg45ProfileEvaluator gpg45ProfileEvaluator;
    @Mock private AuditService auditService;
    @Mock private ClientOAuthSessionDetailsService clientOAuthSessionDetailsService;
    @Mock private SessionCredentialsService sessionCredentialsService;
    @Mock private CimitUtilityService cimitUtilityService;
    @InjectMocks private EvaluateGpg45ScoresHandler evaluateGpg45ScoresHandler;

    @Spy private IpvSessionItem ipvSessionItem;
    private ClientOAuthSessionItem clientOAuthSessionItem;

    @BeforeAll
    static void setUp() {
        request =
                JourneyRequest.builder()
                        .ipvSessionId(TEST_SESSION_ID)
                        .ipAddress(TEST_CLIENT_SOURCE_IP)
                        .build();
    }

    @BeforeEach
    void setUpEach() {
        ipvSessionItem.setClientOAuthSessionId(TEST_CLIENT_OAUTH_SESSION_ID);
        ipvSessionItem.setIpvSessionId(TEST_SESSION_ID);
        ipvSessionItem.setTargetVot(Vot.P2);

        clientOAuthSessionItem =
                ClientOAuthSessionItem.builder()
                        .clientOAuthSessionId(TEST_CLIENT_OAUTH_SESSION_ID)
                        .state("test-state")
                        .vtr(List.of("P2"))
                        .responseType("code")
                        .redirectUri("https://example.com/redirect")
                        .govukSigninJourneyId("test-journey-id")
                        .userId(TEST_USER_ID)
                        .clientId("test-client")
                        .govukSigninJourneyId(TEST_JOURNEY_ID)
                        .build();
    }

    @AfterEach
    void checkAuditEventWait() {
        InOrder auditInOrder = inOrder(auditService);
        auditInOrder.verify(auditService).awaitAuditEvents();
        auditInOrder.verifyNoMoreInteractions();
    }

    @Test
    void shouldReturnJourneyMetIfScoresSatisfyM1AGpg45Profile() throws Exception {
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(gpg45ProfileEvaluator.getFirstMatchingProfile(any(), eq(P2_PROFILES)))
                .thenReturn(Optional.of(M1A));
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(userIdentityService.areVcsCorrelated(any())).thenReturn(true);

        JourneyResponse response =
                toResponseClass(
                        evaluateGpg45ScoresHandler.handleRequest(request, context),
                        JourneyResponse.class);

        assertEquals(JOURNEY_MET.getJourney(), response.getJourney());

        verify(sessionCredentialsService).getCredentials(TEST_SESSION_ID, TEST_USER_ID);
        verify(clientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());

        InOrder inOrder = inOrder(ipvSessionItem, ipvSessionService);
        inOrder.verify(ipvSessionItem).setVot(Vot.P2);
        inOrder.verify(ipvSessionService).updateIpvSession(ipvSessionItem);
        inOrder.verify(ipvSessionItem, never()).setVot(any());
        assertEquals(Vot.P2, ipvSessionItem.getVot());
    }

    @Test
    void shouldReturnJourneyMetIfScoresSatisfyM1BGpg45Profile() throws Exception {
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(gpg45ProfileEvaluator.buildScore(any())).thenReturn(new Gpg45Scores(1, 1, 1, 1, 1));
        when(gpg45ProfileEvaluator.getFirstMatchingProfile(any(), eq(P2_PROFILES)))
                .thenReturn(Optional.of(M1B));
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(userIdentityService.areVcsCorrelated(any())).thenReturn(true);

        JourneyResponse response =
                toResponseClass(
                        evaluateGpg45ScoresHandler.handleRequest(request, context),
                        JourneyResponse.class);

        assertEquals(JOURNEY_MET.getJourney(), response.getJourney());
        verify(sessionCredentialsService).getCredentials(TEST_SESSION_ID, TEST_USER_ID);
        verify(clientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());

        InOrder inOrder = inOrder(ipvSessionItem, ipvSessionService);
        inOrder.verify(ipvSessionItem).setVot(Vot.P2);
        inOrder.verify(ipvSessionService).updateIpvSession(ipvSessionItem);
        inOrder.verify(ipvSessionItem, never()).setVot(any());
        assertEquals(Vot.P2, ipvSessionItem.getVot());
    }

    @Test
    void shouldReturnJourneyUnmetIfScoresDoNotSatisfyM1AGpg45Profile() throws Exception {
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(gpg45ProfileEvaluator.getFirstMatchingProfile(any(), eq(P2_PROFILES)))
                .thenReturn(Optional.empty());
        when(gpg45ProfileEvaluator.buildScore(any()))
                .thenReturn(new Gpg45Scores(Gpg45Scores.EV_42, 0, 0, 0));
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(userIdentityService.areVcsCorrelated(any())).thenReturn(true);

        JourneyResponse response =
                toResponseClass(
                        evaluateGpg45ScoresHandler.handleRequest(request, context),
                        JourneyResponse.class);

        assertEquals(JOURNEY_UNMET.getJourney(), response.getJourney());
        verify(sessionCredentialsService).getCredentials(TEST_SESSION_ID, TEST_USER_ID);
        verify(clientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());

        verify(ipvSessionItem, never()).setVot(any());
        assertNull(ipvSessionItem.getVot());
    }

    @Test
    void shouldReturnJourneyUnmetIfGpg45ProfileNotMatched()
            throws HttpResponseExceptionWithErrorBody, IpvSessionNotFoundException {
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(userIdentityService.areVcsCorrelated(any())).thenReturn(true);

        JourneyResponse response =
                toResponseClass(
                        evaluateGpg45ScoresHandler.handleRequest(request, context),
                        JourneyResponse.class);

        assertEquals(JOURNEY_UNMET.getJourney(), response.getJourney());

        verify(ipvSessionItem, never()).setVot(any());
        assertNull(ipvSessionItem.getVot());
    }

    @Test
    void shouldReturn400IfSessionIdNotInRequest() throws Exception {
        JourneyRequest requestWithoutSessionId =
                JourneyRequest.builder().ipAddress(TEST_CLIENT_SOURCE_IP).build();

        JourneyErrorResponse response =
                toResponseClass(
                        evaluateGpg45ScoresHandler.handleRequest(requestWithoutSessionId, context),
                        JourneyErrorResponse.class);

        assertEquals(HttpStatusCode.BAD_REQUEST, response.getStatusCode());
        assertEquals(ErrorResponse.MISSING_IPV_SESSION_ID.getCode(), response.getCode());
        verify(clientOAuthSessionDetailsService, times(0)).getClientOAuthSession(any());
        verify(ipvSessionService, never()).updateIpvSession(any());

        verify(ipvSessionItem, never()).setVot(any());
        assertNull(ipvSessionItem.getVot());
    }

    @Test
    void shouldReturnJourneyErrorIfCantReadSessionCredentials() throws Exception {
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(sessionCredentialsService.getCredentials(TEST_SESSION_ID, TEST_USER_ID))
                .thenThrow(
                        new VerifiableCredentialException(
                                SC_SERVER_ERROR, FAILED_TO_PARSE_ISSUED_CREDENTIALS));

        JourneyErrorResponse response =
                toResponseClass(
                        evaluateGpg45ScoresHandler.handleRequest(request, context),
                        JourneyErrorResponse.class);

        assertEquals(JOURNEY_ERROR.getJourney(), response.getJourney());
        assertEquals(FAILED_TO_PARSE_ISSUED_CREDENTIALS.getMessage(), response.getMessage());
    }

    @Test
    void shouldSendAuditEventWhenProfileMatched() throws Exception {
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(sessionCredentialsService.getCredentials(TEST_SESSION_ID, TEST_USER_ID))
                .thenReturn(
                        List.of(
                                PASSPORT_NON_DCMAW_SUCCESSFUL_VC,
                                M1A_ADDRESS_VC,
                                M1A_EXPERIAN_FRAUD_VC,
                                vcVerificationM1a()));
        when(userIdentityService.areVcsCorrelated(any())).thenReturn(true);
        when(gpg45ProfileEvaluator.getFirstMatchingProfile(any(), eq(P2_PROFILES)))
                .thenReturn(Optional.of(M1A));
        when(gpg45ProfileEvaluator.buildScore(any()))
                .thenReturn(new Gpg45Scores(Gpg45Scores.EV_42, 0, 1, 2));
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        evaluateGpg45ScoresHandler.handleRequest(request, context);

        ArgumentCaptor<AuditEvent> auditEventCaptor = ArgumentCaptor.forClass(AuditEvent.class);
        verify(auditService).sendAuditEvent(auditEventCaptor.capture());
        AuditEvent auditEvent = auditEventCaptor.getValue();

        assertEquals(AuditEventTypes.IPV_GPG45_PROFILE_MATCHED, auditEvent.getEventName());

        AuditEventUser user = auditEvent.getUser();
        assertEquals(TEST_USER_ID, user.getUserId());
        assertEquals(TEST_JOURNEY_ID, user.getGovukSigninJourneyId());
        assertEquals(TEST_SESSION_ID, user.getSessionId());

        AuditExtensionGpg45ProfileMatched extension =
                (AuditExtensionGpg45ProfileMatched) auditEvent.getExtensions();
        assertEquals(M1A, extension.getGpg45Profile());
        assertEquals(new Gpg45Scores(Gpg45Scores.EV_42, 0, 1, 2), extension.getGpg45Scores());
        assertEquals(
                List.of("1c04edf0-a205-4585-8877-be6bd1776a39", "RB000103490087", "abc1234"),
                extension.getVcTxnIds());
        verify(clientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());
        InOrder inOrder = inOrder(ipvSessionItem, ipvSessionService);
        inOrder.verify(ipvSessionItem).setVot(Vot.P2);
        inOrder.verify(ipvSessionService).updateIpvSession(ipvSessionItem);
        inOrder.verify(ipvSessionItem, never()).setVot(any());
        assertEquals(Vot.P2, ipvSessionItem.getVot());
    }

    @Test
    void shouldAddM1cToProfilesWhenAllowed() throws Exception {
        // Arrange
        var vcs =
                List.of(
                        DCMAW_PASSPORT_VC,
                        M1A_ADDRESS_VC,
                        vcFraudApplicableAuthoritativeSourceFailed(),
                        vcVerificationM1a());
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(sessionCredentialsService.getCredentials(TEST_SESSION_ID, TEST_USER_ID))
                .thenReturn(vcs);
        when(userIdentityService.areVcsCorrelated(any())).thenReturn(true);
        when(gpg45ProfileEvaluator.getFirstMatchingProfile(any(), eq(P2_PROFILES_PLUS_M1C)))
                .thenReturn(Optional.of(M1C));
        when(gpg45ProfileEvaluator.buildScore(any()))
                .thenReturn(new Gpg45Scores(Gpg45Scores.EV_33, 0, 0, 2));
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        // Act
        evaluateGpg45ScoresHandler.handleRequest(request, context);

        // Assert
        verify(gpg45ProfileEvaluator).getFirstMatchingProfile(any(), eq(P2_PROFILES_PLUS_M1C));
        assertEquals(Vot.P2, ipvSessionItem.getVot());
    }

    @Test
    void shouldNotAddM1cToProfilesWhenNotAllowed() throws Exception {
        // Arrange
        var vcs =
                List.of(
                        DCMAW_PASSPORT_VC,
                        M1A_ADDRESS_VC,
                        vcExperianFraudScoreOne(),
                        vcVerificationM1a());
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(sessionCredentialsService.getCredentials(TEST_SESSION_ID, TEST_USER_ID))
                .thenReturn(vcs);
        when(userIdentityService.areVcsCorrelated(any())).thenReturn(true);
        when(gpg45ProfileEvaluator.getFirstMatchingProfile(any(), eq(P2_PROFILES)))
                .thenReturn(Optional.empty());
        when(gpg45ProfileEvaluator.buildScore(any()))
                .thenReturn(new Gpg45Scores(Gpg45Scores.EV_33, 0, 0, 2));
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);

        // Act
        evaluateGpg45ScoresHandler.handleRequest(request, context);

        // Assert
        verify(gpg45ProfileEvaluator).getFirstMatchingProfile(any(), eq(P2_PROFILES));
    }

    @Test
    void shouldReturnVcsNotCorrelatedIfFailedDueToNameCorrelationIssues() throws Exception {
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(userIdentityService.areVcsCorrelated(any())).thenReturn(false);

        JourneyResponse response =
                toResponseClass(
                        evaluateGpg45ScoresHandler.handleRequest(request, context),
                        JourneyResponse.class);

        assertEquals(JOURNEY_VCS_NOT_CORRELATED, response.getJourney());

        verify(clientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());
        verify(userIdentityService, times(1)).areVcsCorrelated(any());

        verify(ipvSessionService, never()).updateIpvSession(any());

        verify(ipvSessionItem, never()).setVot(any());
        assertNull(ipvSessionItem.getVot());
    }

    @Test
    void shouldReturnJourneyUnmetIfCheckRequiresAdditionalEvidenceResponseTrue() throws Exception {
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(userIdentityService.areVcsCorrelated(any())).thenReturn(true);

        when(userIdentityService.checkRequiresAdditionalEvidence(any())).thenReturn(true);

        JourneyResponse response =
                toResponseClass(
                        evaluateGpg45ScoresHandler.handleRequest(request, context),
                        JourneyResponse.class);

        assertEquals(JOURNEY_UNMET.getJourney(), response.getJourney());
        verify(sessionCredentialsService).getCredentials(TEST_SESSION_ID, TEST_USER_ID);
        verify(clientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());

        verify(ipvSessionItem, never()).setVot(any());
        assertNull(ipvSessionItem.getVot());
        verify(userIdentityService, times(1)).checkRequiresAdditionalEvidence(any());
    }

    @Test
    void shouldReturnJourneyMetIfCheckRequiresAdditionalEvidenceResponseFalse() throws Exception {
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(gpg45ProfileEvaluator.getFirstMatchingProfile(any(), eq(P2_PROFILES)))
                .thenReturn(Optional.of(M1A));
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(userIdentityService.areVcsCorrelated(any())).thenReturn(true);

        when(userIdentityService.checkRequiresAdditionalEvidence(any())).thenReturn(false);

        JourneyResponse response =
                toResponseClass(
                        evaluateGpg45ScoresHandler.handleRequest(request, context),
                        JourneyResponse.class);

        assertEquals(JOURNEY_MET.getJourney(), response.getJourney());
        verify(sessionCredentialsService).getCredentials(TEST_SESSION_ID, TEST_USER_ID);

        verify(clientOAuthSessionDetailsService, times(1)).getClientOAuthSession(any());

        InOrder inOrder = inOrder(ipvSessionItem, ipvSessionService);
        inOrder.verify(ipvSessionItem).setVot(Vot.P2);
        inOrder.verify(ipvSessionService).updateIpvSession(ipvSessionItem);
        inOrder.verify(ipvSessionItem, never()).setVot(any());
        assertEquals(Vot.P2, ipvSessionItem.getVot());
        verify(userIdentityService, times(1)).checkRequiresAdditionalEvidence(any());
    }

    @Test
    void shouldReturnJourneyMetForLowConfidence() throws Exception {
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        when(gpg45ProfileEvaluator.getFirstMatchingProfile(any(), eq(P1_PROFILES)))
                .thenReturn(Optional.of(L1A));
        clientOAuthSessionItem.setVtr(List.of("P1"));
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(userIdentityService.areVcsCorrelated(any())).thenReturn(true);
        when(userIdentityService.checkRequiresAdditionalEvidence(any())).thenReturn(false);

        JourneyResponse response =
                toResponseClass(
                        evaluateGpg45ScoresHandler.handleRequest(request, context),
                        JourneyResponse.class);

        assertEquals(JOURNEY_MET.getJourney(), response.getJourney());

        assertEquals(Vot.P1, ipvSessionItem.getVot());

        ArgumentCaptor<AuditEvent> auditEventCaptor = ArgumentCaptor.forClass(AuditEvent.class);
        verify(auditService).sendAuditEvent(auditEventCaptor.capture());
        AuditEvent auditEvent = auditEventCaptor.getValue();
        AuditExtensionGpg45ProfileMatched extension =
                (AuditExtensionGpg45ProfileMatched) auditEvent.getExtensions();
        assertEquals(L1A, extension.getGpg45Profile());
    }

    @Test
    void shouldReturnJourneyMetForMeetingMediumAndLowConfidences() throws Exception {
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        clientOAuthSessionItem.setVtr(List.of("P1", "P2"));
        ipvSessionItem.setTargetVot(Vot.P1);
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(gpg45ProfileEvaluator.getFirstMatchingProfile(any(), eq(P2_PROFILES)))
                .thenReturn(Optional.of(M1A));
        when(userIdentityService.areVcsCorrelated(any())).thenReturn(true);
        when(userIdentityService.checkRequiresAdditionalEvidence(any())).thenReturn(false);

        JourneyResponse response =
                toResponseClass(
                        evaluateGpg45ScoresHandler.handleRequest(request, context),
                        JourneyResponse.class);

        assertEquals(JOURNEY_MET.getJourney(), response.getJourney());
        verify(ipvSessionItem).setVot(Vot.P2);
    }

    @Test
    void shouldReturnJourneyMetForMeetingMediumConfidencesWhenVtrIncludesVotWithNoGpg45Profiles()
            throws Exception {
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        clientOAuthSessionItem.setVtr(List.of("P1", "P2", "PCL200"));
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(gpg45ProfileEvaluator.getFirstMatchingProfile(any(), eq(P2_PROFILES)))
                .thenReturn(Optional.of(M1A));
        when(userIdentityService.areVcsCorrelated(any())).thenReturn(true);
        when(userIdentityService.checkRequiresAdditionalEvidence(any())).thenReturn(false);

        JourneyResponse response =
                toResponseClass(
                        evaluateGpg45ScoresHandler.handleRequest(request, context),
                        JourneyResponse.class);

        assertEquals(JOURNEY_MET.getJourney(), response.getJourney());
        verify(ipvSessionItem).setVot(Vot.P2);
    }

    @Test
    void shouldNotReturnJourneyMetCiBreaches() throws Exception {
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        clientOAuthSessionItem.setVtr(List.of("P1", "P2", "PCL200"));
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(gpg45ProfileEvaluator.getFirstMatchingProfile(any(), eq(P2_PROFILES)))
                .thenReturn(Optional.of(M1A));
        when(gpg45ProfileEvaluator.getFirstMatchingProfile(any(), eq(P1_PROFILES)))
                .thenReturn(Optional.of(L1A));
        when(cimitUtilityService.getContraIndicatorsFromVc(any(), any()))
                .thenReturn(CONTRAINDICATORS);
        when(cimitUtilityService.isBreachingCiThreshold(CONTRAINDICATORS, Vot.P2)).thenReturn(true);
        when(cimitUtilityService.isBreachingCiThreshold(CONTRAINDICATORS, Vot.P1)).thenReturn(true);
        when(userIdentityService.areVcsCorrelated(any())).thenReturn(true);
        when(userIdentityService.checkRequiresAdditionalEvidence(any())).thenReturn(false);

        JourneyResponse response =
                toResponseClass(
                        evaluateGpg45ScoresHandler.handleRequest(request, context),
                        JourneyResponse.class);

        assertEquals(JOURNEY_UNMET.getJourney(), response.getJourney());
        verify(ipvSessionItem, never()).setVot(any());
    }

    @Test
    void shouldReturnJourneyMetForMeetingLowConfidencesWhenMediumConfidenceBreachesCis()
            throws Exception {
        when(ipvSessionService.getIpvSession(TEST_SESSION_ID)).thenReturn(ipvSessionItem);
        clientOAuthSessionItem.setVtr(List.of("P1", "P2", "PCL200"));
        when(clientOAuthSessionDetailsService.getClientOAuthSession(any()))
                .thenReturn(clientOAuthSessionItem);
        when(gpg45ProfileEvaluator.getFirstMatchingProfile(any(), eq(P2_PROFILES)))
                .thenReturn(Optional.of(M1A));
        when(gpg45ProfileEvaluator.getFirstMatchingProfile(any(), eq(P1_PROFILES)))
                .thenReturn(Optional.of(L1A));
        when(cimitUtilityService.getContraIndicatorsFromVc(any(), any()))
                .thenReturn(CONTRAINDICATORS);
        when(cimitUtilityService.isBreachingCiThreshold(CONTRAINDICATORS, Vot.P2)).thenReturn(true);
        when(cimitUtilityService.isBreachingCiThreshold(CONTRAINDICATORS, Vot.P1))
                .thenReturn(false);
        when(userIdentityService.areVcsCorrelated(any())).thenReturn(true);
        when(userIdentityService.checkRequiresAdditionalEvidence(any())).thenReturn(false);

        JourneyResponse response =
                toResponseClass(
                        evaluateGpg45ScoresHandler.handleRequest(request, context),
                        JourneyResponse.class);

        assertEquals(JOURNEY_MET.getJourney(), response.getJourney());
        verify(ipvSessionItem).setVot(Vot.P1);
    }

    @Test
    void shouldLogRuntimeExceptionsAndRethrow() throws Exception {
        // Arrange
        when(ipvSessionService.getIpvSession(anyString()))
                .thenThrow(new RuntimeException("Test error"));

        var logCollector = LogCollector.getLogCollectorFor(EvaluateGpg45ScoresHandler.class);

        // Act
        var thrown =
                assertThrows(
                        Exception.class,
                        () -> evaluateGpg45ScoresHandler.handleRequest(request, context),
                        "Expected handleRequest() to throw, but it didn't");

        // Assert
        assertEquals("Test error", thrown.getMessage());
        var logMessage = logCollector.getLogMessages().get(0);
        assertThat(logMessage, containsString("Unhandled lambda exception"));
        assertThat(logMessage, containsString("Test error"));
    }

    private <T> T toResponseClass(Map<String, Object> handlerOutput, Class<T> responseClass) {
        return OBJECT_MAPPER.convertValue(handlerOutput, responseClass);
    }
}
