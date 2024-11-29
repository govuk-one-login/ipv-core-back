package uk.gov.di.ipv.core.library.service;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.gpg45.Gpg45ProfileEvaluator;
import uk.gov.di.ipv.core.library.gpg45.Gpg45Scores;
import uk.gov.di.model.ContraIndicator;

import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.enums.Vot.P1;
import static uk.gov.di.ipv.core.library.enums.Vot.P2;
import static uk.gov.di.ipv.core.library.enums.Vot.PCL200;
import static uk.gov.di.ipv.core.library.enums.Vot.PCL250;
import static uk.gov.di.ipv.core.library.enums.Vot.SUPPORTED_VOTS_BY_DESCENDING_STRENGTH;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcExperianFraudScoreTwo;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcHmrcMigrationPCL200;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcHmrcMigrationPCL250;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcVerificationM1a;
import static uk.gov.di.ipv.core.library.gpg45.enums.Gpg45Profile.L1A;
import static uk.gov.di.ipv.core.library.gpg45.enums.Gpg45Profile.M1A;

@ExtendWith(MockitoExtension.class)
public class VotMatcherTest {
    private static final Gpg45Scores GPG_45_SCORES = Gpg45Scores.builder().build();
    private static VerifiableCredential pcl200vc;
    private static VerifiableCredential pcl250vc;
    private static List<VerifiableCredential> gpg45Vcs;

    @Mock private UserIdentityService mockUseridentityService;
    @Mock private Gpg45ProfileEvaluator mockGpg45ProfileEvaluator;
    @Mock private CimitUtilityService mockCimitUtilityService;
    @InjectMocks private VotMatcher votMatcher;

    @BeforeAll
    public static void beforeAll() throws Exception {
        gpg45Vcs = List.of(vcExperianFraudScoreTwo(), vcVerificationM1a());
        pcl200vc = vcHmrcMigrationPCL200();
        pcl250vc = vcHmrcMigrationPCL250();
    }

    @Test
    void shouldReturnFirstMatchedGpg45VotAndProfile() throws Exception {
        when(mockUseridentityService.checkRequiresAdditionalEvidence(gpg45Vcs)).thenReturn(false);
        when(mockGpg45ProfileEvaluator.getFirstMatchingProfile(
                        GPG_45_SCORES, P2.getSupportedGpg45Profiles()))
                .thenReturn(Optional.empty());
        when(mockGpg45ProfileEvaluator.getFirstMatchingProfile(
                        GPG_45_SCORES, P1.getSupportedGpg45Profiles()))
                .thenReturn(Optional.of(L1A));

        var votAndProfile =
                votMatcher.matchFirstVot(
                        SUPPORTED_VOTS_BY_DESCENDING_STRENGTH,
                        gpg45Vcs,
                        GPG_45_SCORES,
                        true,
                        List.of(),
                        List.of());

        assertEquals(Optional.of(new VotAndProfile(P1, L1A)), votAndProfile);
    }

    @Test
    void shouldReturnFirstMatchedOperationalVot() throws Exception {
        var operationalVcs = List.of(pcl200vc);

        when(mockUseridentityService.checkRequiresAdditionalEvidence(gpg45Vcs)).thenReturn(false);

        var votAndProfile =
                votMatcher.matchFirstVot(
                        SUPPORTED_VOTS_BY_DESCENDING_STRENGTH,
                        gpg45Vcs,
                        GPG_45_SCORES,
                        true,
                        operationalVcs,
                        List.of());

        assertEquals(Optional.of(new VotAndProfile(PCL200, null)), votAndProfile);
    }

    @Test
    void shouldReturnEmptyOptionalIfNoVotMatched() throws Exception {
        var votAndProfile =
                votMatcher.matchFirstVot(
                        SUPPORTED_VOTS_BY_DESCENDING_STRENGTH,
                        List.of(),
                        GPG_45_SCORES,
                        true,
                        List.of(),
                        List.of());

        assertEquals(Optional.empty(), votAndProfile);
    }

    @Test
    void shouldMatchWeakerGpg45VotIfStrongerVotHasBreachingCi() throws Exception {
        var contraIndicators = List.of(new ContraIndicator());

        when(mockUseridentityService.checkRequiresAdditionalEvidence(gpg45Vcs)).thenReturn(false);
        when(mockGpg45ProfileEvaluator.getFirstMatchingProfile(
                        GPG_45_SCORES, P2.getSupportedGpg45Profiles()))
                .thenReturn(Optional.of(M1A));
        when(mockGpg45ProfileEvaluator.getFirstMatchingProfile(
                        GPG_45_SCORES, P1.getSupportedGpg45Profiles()))
                .thenReturn(Optional.of(L1A));
        when(mockCimitUtilityService.isBreachingCiThreshold(contraIndicators, P2)).thenReturn(true);

        var votAndProfile =
                votMatcher.matchFirstVot(
                        SUPPORTED_VOTS_BY_DESCENDING_STRENGTH,
                        gpg45Vcs,
                        GPG_45_SCORES,
                        true,
                        List.of(),
                        contraIndicators);

        assertEquals(Optional.of(new VotAndProfile(P1, L1A)), votAndProfile);
    }

    @Test
    void shouldMatchWeakerOperationalVotIfStrongerVotHasBreachingCi() throws Exception {
        var operationalVcs = List.of(pcl250vc, pcl200vc);
        var contraIndicators = List.of(new ContraIndicator());

        when(mockCimitUtilityService.isBreachingCiThreshold(contraIndicators, PCL250))
                .thenReturn(true);

        var votAndProfile =
                votMatcher.matchFirstVot(
                        SUPPORTED_VOTS_BY_DESCENDING_STRENGTH,
                        gpg45Vcs,
                        GPG_45_SCORES,
                        true,
                        operationalVcs,
                        contraIndicators);

        assertEquals(Optional.of(new VotAndProfile(PCL200, null)), votAndProfile);
    }

    @Test
    void shouldNotMatchGpg45VotIfRequiresAdditionalEvidence() throws Exception {
        when(mockUseridentityService.checkRequiresAdditionalEvidence(gpg45Vcs)).thenReturn(true);

        var votAndProfile =
                votMatcher.matchFirstVot(
                        SUPPORTED_VOTS_BY_DESCENDING_STRENGTH,
                        gpg45Vcs,
                        GPG_45_SCORES,
                        true,
                        List.of(),
                        List.of());

        assertEquals(Optional.empty(), votAndProfile);
    }
}
