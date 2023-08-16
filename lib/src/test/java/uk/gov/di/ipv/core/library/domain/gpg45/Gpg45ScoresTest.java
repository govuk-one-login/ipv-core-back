package uk.gov.di.ipv.core.library.domain.gpg45;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static uk.gov.di.ipv.core.library.domain.gpg45.Gpg45Profile.H2D;
import static uk.gov.di.ipv.core.library.domain.gpg45.Gpg45Profile.M1A;
import static uk.gov.di.ipv.core.library.domain.gpg45.Gpg45Profile.M1B;
import static uk.gov.di.ipv.core.library.domain.gpg45.Gpg45Profile.V2A;
import static uk.gov.di.ipv.core.library.domain.gpg45.Gpg45Scores.EV_00;
import static uk.gov.di.ipv.core.library.domain.gpg45.Gpg45Scores.EV_32;
import static uk.gov.di.ipv.core.library.domain.gpg45.Gpg45Scores.EV_33;
import static uk.gov.di.ipv.core.library.domain.gpg45.Gpg45Scores.EV_42;
import static uk.gov.di.ipv.core.library.domain.gpg45.Gpg45Scores.EV_43;

class Gpg45ScoresTest {

    @Test
    void shouldOrderEvidenceOnScoreAndValidity() {
        Gpg45Scores score1 = new Gpg45Scores(EV_33, EV_32, 0, 1, 3);
        Gpg45Scores score2 = new Gpg45Scores(EV_32, EV_33, 0, 1, 3);

        assertTrue(H2D.isSatisfiedBy(score1));
        assertTrue(H2D.isSatisfiedBy(score2));
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

    @Test
    void getEvidenceShouldReturnEvidenceWithZeroScoresWhenNoEvidences() {
        Gpg45Scores gpg45Scores = new Gpg45Scores(List.of(), 0, 1, 3);
        assertEquals(new Gpg45Scores.Evidence(0, 0), gpg45Scores.getEvidence(0));
    }

    @Test
    void calculateRequiredScoresShouldReturnScoresRequiredToMeetGivenProfile() {
        assertEquals(
                new Gpg45Scores(EV_42, 0, 0, 2),
                new Gpg45Scores(0, 0, 0, 1, 0).calculateRequiredScores(M1A));
        assertEquals(
                new Gpg45Scores(EV_42, 0, 0, 2),
                new Gpg45Scores(0, 0, 0, 2, 0).calculateRequiredScores(M1A));
        assertEquals(
                new Gpg45Scores(EV_32, 1, 2, 2),
                new Gpg45Scores(0, 0, 0, 1, 0).calculateRequiredScores(M1B));
        assertEquals(
                new Gpg45Scores(EV_32, 1, 0, 2),
                new Gpg45Scores(0, 0, 0, 2, 0).calculateRequiredScores(M1B));
        assertEquals(
                new Gpg45Scores(List.of(EV_33, EV_00), 3, 0, 3),
                new Gpg45Scores(List.of(EV_00, EV_43), 0, 2, 0).calculateRequiredScores(V2A));
        assertEquals(
                new Gpg45Scores(EV_42, 0, 0, 2),
                new Gpg45Scores(List.of(), 0, 1, 0).calculateRequiredScores(M1A));
        assertEquals(
                new Gpg45Scores(EV_42, 0, 0, 2),
                new Gpg45Scores(List.of(), 1, 2, 0).calculateRequiredScores(M1A));
        assertEquals(
                new Gpg45Scores(EV_32, 0, 0, 2),
                new Gpg45Scores(List.of(), 1, 2, 0).calculateRequiredScores(M1B));
    }

    @Test
    void compareToShouldReturnNegativeIfOtherHasALowerScore() {
        Gpg45Scores score1 = new Gpg45Scores(EV_33, EV_32, 0, 1, 3);
        Gpg45Scores score2 = new Gpg45Scores(EV_33, EV_32, 0, 1, 1);

        assertTrue(score1.compareTo(score2) < 0);
    }

    @Test
    void compareToShouldReturnPositiveIfOtherHasAHigherScore() {
        Gpg45Scores score1 = new Gpg45Scores(EV_33, EV_32, 0, 1, 1);
        Gpg45Scores score2 = new Gpg45Scores(EV_33, EV_32, 0, 1, 3);

        assertTrue(score1.compareTo(score2) > 0);
    }

    @Test
    void compareToShouldReturnZeroIfOtherHasSameScore() {
        Gpg45Scores score1 = new Gpg45Scores(EV_33, EV_32, 0, 1, 3);
        Gpg45Scores score2 = new Gpg45Scores(EV_33, EV_32, 0, 1, 3);

        assertEquals(0, score1.compareTo(score2));
    }
}
