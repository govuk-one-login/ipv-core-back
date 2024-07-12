package uk.gov.di.ipv.core.library.gpg45;

import org.junit.jupiter.api.Test;

import java.util.Arrays;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static uk.gov.di.ipv.core.library.gpg45.Gpg45Scores.EV_11;
import static uk.gov.di.ipv.core.library.gpg45.Gpg45Scores.EV_22;
import static uk.gov.di.ipv.core.library.gpg45.Gpg45Scores.EV_32;
import static uk.gov.di.ipv.core.library.gpg45.Gpg45Scores.EV_33;
import static uk.gov.di.ipv.core.library.gpg45.Gpg45Scores.EV_42;
import static uk.gov.di.ipv.core.library.gpg45.enums.Gpg45Profile.H2D;
import static uk.gov.di.ipv.core.library.gpg45.enums.Gpg45Profile.M1A;
import static uk.gov.di.ipv.core.library.gpg45.enums.Gpg45Profile.M1B;

class Gpg45ScoresTest {

    @Test
    void shouldOrderEvidenceOnScoreAndValidity() {
        Gpg45Scores score1 = new Gpg45Scores(EV_33, EV_32, 0, 1, 3);
        Gpg45Scores score2 = new Gpg45Scores(EV_32, EV_33, 0, 1, 3);

        assertTrue(H2D.isSatisfiedBy(score1));
        assertTrue(H2D.isSatisfiedBy(score2));
    }

    @Test
    void calculateGpg45ScoresRequiredToMeetAProfile() {
        assertEquals(
                Arrays.asList(new Gpg45Scores(EV_42, 0, 0, 2)),
                new Gpg45Scores(0, 0, 0, 1, 0)
                        .calculateGpg45ScoresRequiredToMeetAProfile(Arrays.asList(M1A)));
        assertEquals(
                Arrays.asList(new Gpg45Scores(EV_42, 0, 0, 2)),
                new Gpg45Scores(0, 0, 0, 2, 0)
                        .calculateGpg45ScoresRequiredToMeetAProfile(Arrays.asList(M1A)));
        assertEquals(
                Arrays.asList(new Gpg45Scores(EV_32, 1, 2, 2)),
                new Gpg45Scores(0, 0, 0, 1, 0)
                        .calculateGpg45ScoresRequiredToMeetAProfile(Arrays.asList(M1B)));
        assertEquals(
                Arrays.asList(new Gpg45Scores(EV_32, 1, 0, 2)),
                new Gpg45Scores(0, 0, 0, 2, 0)
                        .calculateGpg45ScoresRequiredToMeetAProfile(Arrays.asList(M1B)));
        assertEquals(
                Arrays.asList(new Gpg45Scores(EV_42, 0, 0, 2)),
                new Gpg45Scores(List.of(), 0, 1, 0)
                        .calculateGpg45ScoresRequiredToMeetAProfile(Arrays.asList(M1A)));
        assertEquals(
                Arrays.asList(new Gpg45Scores(EV_42, 0, 0, 2)),
                new Gpg45Scores(List.of(), 1, 2, 0)
                        .calculateGpg45ScoresRequiredToMeetAProfile(Arrays.asList(M1A)));
        assertEquals(
                Arrays.asList(new Gpg45Scores(EV_32, 0, 0, 2)),
                new Gpg45Scores(List.of(), 1, 2, 0)
                        .calculateGpg45ScoresRequiredToMeetAProfile(Arrays.asList(M1B)));
        assertEquals(
                Arrays.asList(new Gpg45Scores(List.of(), 0, 0, 2)),
                new Gpg45Scores(EV_32, 1, 2, 0)
                        .calculateGpg45ScoresRequiredToMeetAProfile(Arrays.asList(M1B)));
        assertEquals(
                Arrays.asList(new Gpg45Scores(EV_32, 0, 0, 2)),
                new Gpg45Scores(EV_11, 1, 2, 0)
                        .calculateGpg45ScoresRequiredToMeetAProfile(Arrays.asList(M1B)));
        assertEquals(
                Arrays.asList(new Gpg45Scores(EV_32, 0, 0, 2)),
                new Gpg45Scores(EV_22, 1, 2, 0)
                        .calculateGpg45ScoresRequiredToMeetAProfile(Arrays.asList(M1B)));
    }

    @Test
    void shouldBuild() {
        var scores =
                new Gpg45Scores.Builder()
                        .withEvidence(new Gpg45Scores.Evidence(2, 2))
                        .withActivity(1)
                        .withFraud(1)
                        .withVerification(1)
                        .build();
        assertEquals(new Gpg45Scores(2, 2, 1, 1, 1), scores);
    }

    @Test
    void shouldProduceReadableToString() {
        var scores =
                new Gpg45Scores.Builder()
                        .withEvidence(new Gpg45Scores.Evidence(2, 2))
                        .withEvidence(new Gpg45Scores.Evidence(3, 2))
                        .withActivity(1)
                        .withFraud(2)
                        .withVerification(3)
                        .build();

        assertEquals("[[32, 22], 1, 2, 3]", scores.toString());
    }
}
