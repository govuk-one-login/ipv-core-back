package uk.gov.di.ipv.core.library.useridentity.service;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.domain.VerifiableCredential;
import uk.gov.di.ipv.core.library.gpg45.Gpg45ProfileEvaluator;
import uk.gov.di.ipv.core.library.gpg45.Gpg45Scores;
import uk.gov.di.ipv.core.library.gpg45.enums.Gpg45Profile;
import uk.gov.di.ipv.core.library.service.CimitUtilityService;
import uk.gov.di.model.ContraIndicator;

import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.enums.Vot.P1;
import static uk.gov.di.ipv.core.library.enums.Vot.P2;
import static uk.gov.di.ipv.core.library.enums.Vot.PCL200;
import static uk.gov.di.ipv.core.library.enums.Vot.PCL250;
import static uk.gov.di.ipv.core.library.enums.Vot.SUPPORTED_VOTS_BY_DESCENDING_STRENGTH;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcExperianFraudApplicableAuthoritativeSourceFailed;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcExperianFraudAvailableAuthoritativeFailed;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcExperianFraudScoreTwo;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcHmrcMigrationPCL200;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcHmrcMigrationPCL250;
import static uk.gov.di.ipv.core.library.fixtures.VcFixtures.vcVerificationM1a;
import static uk.gov.di.ipv.core.library.gpg45.enums.Gpg45Profile.L1A;
import static uk.gov.di.ipv.core.library.gpg45.enums.Gpg45Profile.M1A;

@ExtendWith(MockitoExtension.class)
class VotMatcherTest {
    private static final Gpg45Scores GPG_45_SCORES = Gpg45Scores.builder().build();
    private static VerifiableCredential pcl200vc;
    private static VerifiableCredential pcl250vc;
    private static List<VerifiableCredential> gpg45Vcs;

    @Mock private UserIdentityService mockUseridentityService;
    @Mock private Gpg45ProfileEvaluator mockGpg45ProfileEvaluator;
    @Mock private CimitUtilityService mockCimitUtilityService;
    @InjectMocks private VotMatcher votMatcher;

    @BeforeAll
    static void beforeAll() throws Exception {
        gpg45Vcs = List.of(vcExperianFraudScoreTwo(), vcVerificationM1a());
        pcl200vc = vcHmrcMigrationPCL200();
        pcl250vc = vcHmrcMigrationPCL250();
    }

    @Test
    void shouldReturnFirstMatchedGpg45Vot() throws Exception {
        when(mockUseridentityService.checkRequiresAdditionalEvidence(gpg45Vcs)).thenReturn(false);
        when(mockGpg45ProfileEvaluator.buildScore(gpg45Vcs)).thenReturn(GPG_45_SCORES);
        when(mockGpg45ProfileEvaluator.getFirstMatchingProfile(
                        GPG_45_SCORES, P2.getSupportedGpg45Profiles(true)))
                .thenReturn(Optional.empty());
        when(mockGpg45ProfileEvaluator.getFirstMatchingProfile(
                        GPG_45_SCORES, P1.getSupportedGpg45Profiles(true)))
                .thenReturn(Optional.of(L1A));

        var votMatch =
                votMatcher.matchFirstVot(
                        SUPPORTED_VOTS_BY_DESCENDING_STRENGTH, gpg45Vcs, List.of(), true);

        assertEquals(Optional.of(new VotMatchingResult(P1, L1A, GPG_45_SCORES)), votMatch);
    }

    @Test
    void shouldReturnFirstMatchedOperationalVot() throws Exception {
        when(mockUseridentityService.checkRequiresAdditionalEvidence(gpg45Vcs)).thenReturn(false);

        var votMatch =
                votMatcher.matchFirstVot(
                        SUPPORTED_VOTS_BY_DESCENDING_STRENGTH,
                        Stream.concat(gpg45Vcs.stream(), Stream.of(pcl200vc)).toList(),
                        List.of(),
                        true);

        assertEquals(Optional.of(new VotMatchingResult(PCL200, null, null)), votMatch);
    }

    @Test
    void shouldReturnEmptyOptionalIfNoVotMatched() throws Exception {
        var votMatch =
                votMatcher.matchFirstVot(
                        SUPPORTED_VOTS_BY_DESCENDING_STRENGTH, List.of(), List.of(), true);

        assertEquals(Optional.empty(), votMatch);
    }

    @Test
    void shouldMatchWeakerGpg45VotIfStrongerVotHasBreachingCi() throws Exception {
        var contraIndicators = List.of(new ContraIndicator());

        when(mockGpg45ProfileEvaluator.buildScore(gpg45Vcs)).thenReturn(GPG_45_SCORES);
        when(mockUseridentityService.checkRequiresAdditionalEvidence(gpg45Vcs)).thenReturn(false);
        when(mockGpg45ProfileEvaluator.getFirstMatchingProfile(
                        GPG_45_SCORES, P2.getSupportedGpg45Profiles(true)))
                .thenReturn(Optional.of(M1A));
        when(mockGpg45ProfileEvaluator.getFirstMatchingProfile(
                        GPG_45_SCORES, P1.getSupportedGpg45Profiles(true)))
                .thenReturn(Optional.of(L1A));
        when(mockCimitUtilityService.isBreachingCiThreshold(contraIndicators, P2)).thenReturn(true);

        var votMatch =
                votMatcher.matchFirstVot(
                        SUPPORTED_VOTS_BY_DESCENDING_STRENGTH, gpg45Vcs, contraIndicators, true);

        assertEquals(Optional.of(new VotMatchingResult(P1, L1A, GPG_45_SCORES)), votMatch);
    }

    @Test
    void shouldMatchWeakerOperationalVotIfStrongerVotHasBreachingCi() throws Exception {
        var contraIndicators = List.of(new ContraIndicator());

        when(mockCimitUtilityService.isBreachingCiThreshold(contraIndicators, PCL250))
                .thenReturn(true);

        var votMatch =
                votMatcher.matchFirstVot(
                        SUPPORTED_VOTS_BY_DESCENDING_STRENGTH,
                        Stream.concat(gpg45Vcs.stream(), Stream.of(pcl250vc, pcl200vc)).toList(),
                        contraIndicators,
                        true);

        assertEquals(Optional.of(new VotMatchingResult(PCL200, null, null)), votMatch);
    }

    @Test
    void shouldNotMatchGpg45VotIfRequiresAdditionalEvidence() throws Exception {
        when(mockUseridentityService.checkRequiresAdditionalEvidence(gpg45Vcs)).thenReturn(true);

        var votMatch =
                votMatcher.matchFirstVot(
                        SUPPORTED_VOTS_BY_DESCENDING_STRENGTH, gpg45Vcs, List.of(), true);

        assertEquals(Optional.empty(), votMatch);
    }

    @Test
    void shouldMatchM1cIfFraudCheckUnavailable() throws Exception {
        // Arrange
        var vcs =
                List.of(vcVerificationM1a(), vcExperianFraudApplicableAuthoritativeSourceFailed());
        var expectedProfiles =
                List.of(Gpg45Profile.M1A, Gpg45Profile.M1B, Gpg45Profile.M2B, Gpg45Profile.M1C);
        when(mockUseridentityService.checkRequiresAdditionalEvidence(vcs)).thenReturn(false);
        when(mockGpg45ProfileEvaluator.buildScore(vcs)).thenReturn(GPG_45_SCORES);
        when(mockGpg45ProfileEvaluator.getFirstMatchingProfile(GPG_45_SCORES, expectedProfiles))
                .thenReturn(Optional.of(Gpg45Profile.M1C));

        // Act
        var votMatch =
                votMatcher.matchFirstVot(
                        SUPPORTED_VOTS_BY_DESCENDING_STRENGTH, vcs, List.of(), true);

        // Assert
        verify(mockGpg45ProfileEvaluator).getFirstMatchingProfile(GPG_45_SCORES, expectedProfiles);
        assertEquals(
                Optional.of(new VotMatchingResult(P2, Gpg45Profile.M1C, GPG_45_SCORES)), votMatch);
    }

    @Test
    void shouldMatchM1cIfFraudCheckAuthoritativeUnavailable() throws Exception {
        // Arrange
        var vcs = List.of(vcVerificationM1a(), vcExperianFraudAvailableAuthoritativeFailed());
        var expectedProfiles =
                List.of(Gpg45Profile.M1A, Gpg45Profile.M1B, Gpg45Profile.M2B, Gpg45Profile.M1C);
        when(mockUseridentityService.checkRequiresAdditionalEvidence(vcs)).thenReturn(false);
        when(mockGpg45ProfileEvaluator.buildScore(vcs)).thenReturn(GPG_45_SCORES);
        when(mockGpg45ProfileEvaluator.getFirstMatchingProfile(GPG_45_SCORES, expectedProfiles))
                .thenReturn(Optional.of(Gpg45Profile.M1C));

        // Act
        var votMatch =
                votMatcher.matchFirstVot(
                        SUPPORTED_VOTS_BY_DESCENDING_STRENGTH, vcs, List.of(), true);

        // Assert
        verify(mockGpg45ProfileEvaluator).getFirstMatchingProfile(GPG_45_SCORES, expectedProfiles);
        assertEquals(
                Optional.of(new VotMatchingResult(P2, Gpg45Profile.M1C, GPG_45_SCORES)), votMatch);
    }

    @Test
    void shouldNotMatchM1cIfFraudCheckAvailable() throws Exception {
        // Arrange
        when(mockGpg45ProfileEvaluator.buildScore(gpg45Vcs)).thenReturn(GPG_45_SCORES);
        var expectedProfiles = List.of(Gpg45Profile.M1A, Gpg45Profile.M1B, Gpg45Profile.M2B);
        when(mockUseridentityService.checkRequiresAdditionalEvidence(gpg45Vcs)).thenReturn(false);
        when(mockGpg45ProfileEvaluator.getFirstMatchingProfile(GPG_45_SCORES, expectedProfiles))
                .thenReturn(Optional.of(Gpg45Profile.M2B));

        // Act
        var votMatch =
                votMatcher.matchFirstVot(
                        SUPPORTED_VOTS_BY_DESCENDING_STRENGTH, gpg45Vcs, List.of(), true);

        // Assert
        verify(mockGpg45ProfileEvaluator).getFirstMatchingProfile(GPG_45_SCORES, expectedProfiles);
        assertEquals(
                Optional.of(new VotMatchingResult(P2, Gpg45Profile.M2B, GPG_45_SCORES)), votMatch);
    }
}
