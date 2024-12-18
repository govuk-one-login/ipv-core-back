package uk.gov.di.ipv.core.processcandidateidentity.service;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.auditing.AuditEvent;
import uk.gov.di.ipv.core.library.auditing.AuditEventUser;
import uk.gov.di.ipv.core.library.enums.Vot;
import uk.gov.di.ipv.core.library.gpg45.Gpg45Scores;
import uk.gov.di.ipv.core.library.helpers.SecureTokenHelper;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.CimitUtilityService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.UserIdentityService;
import uk.gov.di.ipv.core.library.service.VotMatcher;
import uk.gov.di.ipv.core.library.service.VotMatchingResult;
import uk.gov.di.model.ContraIndicator;

import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.auditing.AuditEventTypes.IPV_GPG45_PROFILE_MATCHED;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.PASSPORT_NON_DCMAW_SUCCESSFUL_VC;
import static uk.gov.di.ipv.core.library.gpg45.enums.Gpg45Profile.M1A;

@ExtendWith(MockitoExtension.class)
class EvaluateGpg46ScoresServiceTest {
    private static final String TEST_SESSION_ID = "test-session-id";
    private static final String TEST_USER_ID = "test-user-id";
    private static final String TEST_JOURNEY_ID = "test-journey-id";
    private static final List<ContraIndicator> CONTRAINDICATORS = List.of();
    private static final String TEST_CLIENT_OAUTH_SESSION_ID =
            SecureTokenHelper.getInstance().generate();
    private AuditEventUser testAuditEventUser;

    @Mock private ConfigService mockConfigService;
    @Mock private UserIdentityService mockUserIdentityService;
    @Mock private AuditService mockAuditService;
    @Mock private CimitUtilityService mockCimitUtilityService;
    @Mock private VotMatcher mockVotMatcher;
    @InjectMocks EvaluateGpg45ScoresService evaluateGpg45ScoresService;
    @Captor private ArgumentCaptor<AuditEvent> auditEventCaptor;

    @Spy private IpvSessionItem ipvSessionItem;
    private ClientOAuthSessionItem clientOAuthSessionItem;

    @BeforeEach
    void setUpEach() {
        testAuditEventUser =
                new AuditEventUser(TEST_USER_ID, TEST_SESSION_ID, TEST_JOURNEY_ID, "ip-address");
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

    @Test
    void findMatchingGpg45ProfileShouldReturnMatchingProfileIfNoBreachingCis() throws Exception {
        // Arrange
        var mockGpg45Scores = new Gpg45Scores(1, 1, 1, 1, 1);
        when(mockUserIdentityService.checkRequiresAdditionalEvidence(any())).thenReturn(false);
        when(mockVotMatcher.matchFirstVot(any(), any(), any(), anyBoolean()))
                .thenReturn(Optional.of(new VotMatchingResult(Vot.P2, M1A, mockGpg45Scores)));

        var vcs = List.of(PASSPORT_NON_DCMAW_SUCCESSFUL_VC);

        // Act
        var res =
                evaluateGpg45ScoresService.findMatchingGpg45Profile(
                        vcs,
                        clientOAuthSessionItem,
                        "device-information",
                        null,
                        testAuditEventUser);

        // Assert
        assertTrue(res.isPresent());
        assertEquals(M1A, res.get());

        verify(mockAuditService, times(1)).sendAuditEvent(auditEventCaptor.capture());
        var auditEventsCaptured = auditEventCaptor.getAllValues();

        assertEquals(IPV_GPG45_PROFILE_MATCHED, auditEventsCaptured.get(0).getEventName());
    }

    @Test
    void findMatchingGpg45ProfileShouldReturnNoProfilesIfBreachingCi() throws Exception {
        // Arrange
        var mockGpg45Scores = new Gpg45Scores(1, 1, 1, 1, 1);
        when(mockVotMatcher.matchFirstVot(any(), any(), any(), anyBoolean()))
                .thenReturn(Optional.of(new VotMatchingResult(Vot.P2, M1A, mockGpg45Scores)));
        when(mockUserIdentityService.checkRequiresAdditionalEvidence(any())).thenReturn(false);
        when(mockCimitUtilityService.isBreachingCiThreshold(CONTRAINDICATORS, Vot.P2))
                .thenReturn(true);
        var vcs = List.of(PASSPORT_NON_DCMAW_SUCCESSFUL_VC);

        // Act
        var res =
                evaluateGpg45ScoresService.findMatchingGpg45Profile(
                        vcs,
                        clientOAuthSessionItem,
                        "device-information",
                        CONTRAINDICATORS,
                        testAuditEventUser);

        // Assert
        assertTrue(res.isEmpty());
        verify(mockAuditService, times(0)).sendAuditEvent(auditEventCaptor.capture());
    }

    @Test
    void findMatchingGpg45ProfileShouldReturnEmptyIfNoMatchingProfileFound() throws Exception {
        // Arrange
        when(mockVotMatcher.matchFirstVot(any(), any(), any(), anyBoolean()))
                .thenReturn(Optional.empty());
        when(mockUserIdentityService.checkRequiresAdditionalEvidence(any())).thenReturn(false);

        var vcs = List.of(PASSPORT_NON_DCMAW_SUCCESSFUL_VC);

        // Act
        var res =
                evaluateGpg45ScoresService.findMatchingGpg45Profile(
                        vcs,
                        clientOAuthSessionItem,
                        "device-information",
                        CONTRAINDICATORS,
                        testAuditEventUser);

        // Assert
        assertTrue(res.isEmpty());
        verify(mockAuditService, times(0)).sendAuditEvent(auditEventCaptor.capture());
    }

    @Test
    void findMatchingGpg45ProfileShouldReturnEmptyIfCheckRequiresAdditionalEvidenceResponseTrue()
            throws Exception {
        // Arrange
        when(mockUserIdentityService.checkRequiresAdditionalEvidence(any())).thenReturn(true);
        var vcs = List.of(PASSPORT_NON_DCMAW_SUCCESSFUL_VC);

        // Act
        var res =
                evaluateGpg45ScoresService.findMatchingGpg45Profile(
                        vcs,
                        clientOAuthSessionItem,
                        "device-information",
                        CONTRAINDICATORS,
                        testAuditEventUser);

        // Assert
        assertTrue(res.isEmpty());
        verify(mockAuditService, times(0)).sendAuditEvent(auditEventCaptor.capture());
    }
}
