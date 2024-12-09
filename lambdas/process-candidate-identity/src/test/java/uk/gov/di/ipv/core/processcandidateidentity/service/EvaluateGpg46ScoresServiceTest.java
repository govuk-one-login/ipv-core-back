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
import uk.gov.di.ipv.core.library.enums.Vot;
import uk.gov.di.ipv.core.library.gpg45.Gpg45ProfileEvaluator;
import uk.gov.di.ipv.core.library.gpg45.Gpg45Scores;
import uk.gov.di.ipv.core.library.gpg45.enums.Gpg45Profile;
import uk.gov.di.ipv.core.library.helpers.SecureTokenHelper;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.AuditService;
import uk.gov.di.ipv.core.library.service.CimitUtilityService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.library.service.UserIdentityService;
import uk.gov.di.model.ContraIndicator;

import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.auditing.AuditEventTypes.IPV_GPG45_PROFILE_MATCHED;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.PASSPORT_NON_DCMAW_SUCCESSFUL_VC;
import static uk.gov.di.ipv.core.library.gpg45.enums.Gpg45Profile.M1A;
import static uk.gov.di.ipv.core.library.gpg45.enums.Gpg45Profile.M1B;
import static uk.gov.di.ipv.core.library.gpg45.enums.Gpg45Profile.M2B;

@ExtendWith(MockitoExtension.class)
public class EvaluateGpg46ScoresServiceTest {
    private static final String TEST_SESSION_ID = "test-session-id";
    private static final String TEST_USER_ID = "test-user-id";
    private static final String TEST_JOURNEY_ID = "test-journey-id";
    private static final List<Gpg45Profile> P2_PROFILES = List.of(M1A, M1B, M2B);
    private static final List<ContraIndicator> CONTRAINDICATORS = List.of();
    private static final String TEST_CLIENT_OAUTH_SESSION_ID =
            SecureTokenHelper.getInstance().generate();

    @Mock private ConfigService mockConfigService;
    @Mock private UserIdentityService mockUserIdentityService;
    @Mock private Gpg45ProfileEvaluator mockGpg45ProfileEvaluator;
    @Mock private AuditService mockAuditService;
    @Mock private CimitUtilityService mockCimitUtilityService;
    @InjectMocks EvaluateGpg45ScoresService evaluateGpg45ScoresService;
    @Captor private ArgumentCaptor<AuditEvent> auditEventCaptor;

    @Spy private IpvSessionItem ipvSessionItem;
    private ClientOAuthSessionItem clientOAuthSessionItem;

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

    @Test
    void findMatchingGpg45ProfileShouldReturnMatchingProfileIfNoBreachingCis() throws Exception {
        // Arrange
        var mockGpg45Scores = new Gpg45Scores(1, 1, 1, 1, 1);
        when(mockUserIdentityService.checkRequiresAdditionalEvidence(any())).thenReturn(false);
        when(mockGpg45ProfileEvaluator.buildScore(any())).thenReturn(mockGpg45Scores);
        when(mockGpg45ProfileEvaluator.getFirstMatchingProfile(any(), eq(P2_PROFILES)))
                .thenReturn(Optional.of(M1A));
        var vcs = List.of(PASSPORT_NON_DCMAW_SUCCESSFUL_VC);

        // Act
        var res =
                evaluateGpg45ScoresService.findMatchingGpg45Profile(
                        vcs,
                        ipvSessionItem,
                        clientOAuthSessionItem,
                        "ip-address",
                        "devide-information",
                        null);

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
        when(mockUserIdentityService.checkRequiresAdditionalEvidence(any())).thenReturn(false);
        when(mockGpg45ProfileEvaluator.buildScore(any()))
                .thenReturn(new Gpg45Scores(1, 1, 1, 1, 1));
        when(mockGpg45ProfileEvaluator.getFirstMatchingProfile(any(), eq(P2_PROFILES)))
                .thenReturn(Optional.of(M1A));
        when(mockCimitUtilityService.isBreachingCiThreshold(CONTRAINDICATORS, Vot.P2))
                .thenReturn(true);
        var vcs = List.of(PASSPORT_NON_DCMAW_SUCCESSFUL_VC);

        // Act
        var res =
                evaluateGpg45ScoresService.findMatchingGpg45Profile(
                        vcs,
                        ipvSessionItem,
                        clientOAuthSessionItem,
                        "ip-address",
                        "devide-information",
                        CONTRAINDICATORS);

        // Assert
        assertTrue(res.isEmpty());
        verify(mockAuditService, times(0)).sendAuditEvent(auditEventCaptor.capture());
    }

    @Test
    void findMatchingGpg45ProfileShouldReturnEmptyIfNoMatchingProfileFound() throws Exception {
        // Arrange
        when(mockUserIdentityService.checkRequiresAdditionalEvidence(any())).thenReturn(false);
        when(mockGpg45ProfileEvaluator.buildScore(any()))
                .thenReturn(new Gpg45Scores(1, 1, 1, 1, 1));
        when(mockGpg45ProfileEvaluator.getFirstMatchingProfile(any(), eq(P2_PROFILES)))
                .thenReturn(Optional.empty());
        when(mockCimitUtilityService.isBreachingCiThreshold(CONTRAINDICATORS, Vot.P2))
                .thenReturn(true);
        var vcs = List.of(PASSPORT_NON_DCMAW_SUCCESSFUL_VC);

        // Act
        var res =
                evaluateGpg45ScoresService.findMatchingGpg45Profile(
                        vcs,
                        ipvSessionItem,
                        clientOAuthSessionItem,
                        "ip-address",
                        "devide-information",
                        CONTRAINDICATORS);

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
                        ipvSessionItem,
                        clientOAuthSessionItem,
                        "ip-address",
                        "devide-information",
                        CONTRAINDICATORS);

        // Assert
        assertTrue(res.isEmpty());
        verify(mockAuditService, times(0)).sendAuditEvent(auditEventCaptor.capture());
    }
}
