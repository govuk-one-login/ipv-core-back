package uk.gov.di.ipv.core.library.domain.gpg45;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.aggregator.ArgumentsAccessor;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.CsvSource;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import uk.gov.di.ipv.core.library.domain.gpg45.Gpg45Scores.Evidence;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static uk.gov.di.ipv.core.library.domain.gpg45.Gpg45Scores.EV_11;
import static uk.gov.di.ipv.core.library.domain.gpg45.Gpg45Scores.EV_22;
import static uk.gov.di.ipv.core.library.domain.gpg45.Gpg45Scores.EV_32;
import static uk.gov.di.ipv.core.library.domain.gpg45.Gpg45Scores.EV_33;
import static uk.gov.di.ipv.core.library.domain.gpg45.Gpg45Scores.EV_42;
import static uk.gov.di.ipv.core.library.domain.gpg45.Gpg45Scores.EV_43;
import static uk.gov.di.ipv.core.library.domain.gpg45.Gpg45Scores.EV_44;

class Gpg45ProfileTest {

    @Test
    void shouldMatchExact() {
        for (Gpg45Profile profile : Gpg45Profile.values()) {
            assertTrue(profile.isSatisfiedBy(profile.getScores()));
        }
    }

    // H2C needs evidence scores of 33 and 22
    private static Stream<Arguments> ShouldMatchDoubleEvidenceScoresTestCases() {
        return Stream.of(
                Arguments.of(3, 3, 2, 2), // Exact match
                Arguments.of(2, 2, 3, 3), // Exact match reversed
                Arguments.of(4, 2, 3, 3), // Stronger evidence has weaker validity
                Arguments.of(2, 4, 3, 3), // Weaker evidence has stronger validity
                Arguments.of(4, 4, 4, 4) // Higher strength and validity still matches
                );
    }

    @ParameterizedTest
    @MethodSource("ShouldMatchDoubleEvidenceScoresTestCases")
    void shouldMatchDoubleEvidenceScores(
            int evidence1Strength,
            int evidence1Validity,
            int evidence2Strength,
            int evidence2Validity) {
        var evidence1 = new Evidence(evidence1Strength, evidence1Validity);
        var evidence2 = new Evidence(evidence2Strength, evidence2Validity);
        var scoresToTest = new Gpg45Scores(evidence1, evidence2, 1, 1, 3);

        assertTrue(Gpg45Profile.H2C.isSatisfiedBy(scoresToTest));
    }

    // V3A needs evidence scores of 33, 22, and 22
    private static Stream<Arguments> ShouldMatchTripleEvidenceScoresTestCases() {
        return Stream.of(
                Arguments.of(3, 3, 2, 2, 2, 2), // Exact match
                Arguments.of(2, 2, 2, 2, 3, 3), // Exact match reversed
                Arguments.of(4, 2, 3, 3, 2, 2), // Stronger evidence has weaker validity
                Arguments.of(2, 4, 3, 3, 2, 2), // Weaker evidence has stronger validity
                Arguments.of(4, 4, 4, 4, 4, 4) // Higher strength and validity still matches
                );
    }

    @ParameterizedTest
    @MethodSource("ShouldMatchTripleEvidenceScoresTestCases")
    void shouldMatchTripleEvidenceScores(
            int evidence1Strength,
            int evidence1Validity,
            int evidence2Strength,
            int evidence2Validity,
            int evidence3Strength,
            int evidence3Validity) {
        var evidence1 = new Evidence(evidence1Strength, evidence1Validity);
        var evidence2 = new Evidence(evidence2Strength, evidence2Validity);
        var evidence3 = new Evidence(evidence3Strength, evidence3Validity);
        var scoresToTest = new Gpg45Scores(evidence1, evidence2, evidence3, 3, 3, 3);

        assertTrue(Gpg45Profile.V3A.isSatisfiedBy(scoresToTest));
    }

    // L1C requires evidence with strength and validity scores of 1
    @ParameterizedTest
    @CsvSource({"2,1", "3,1", "4,1", "1,2", "1,3", "1,4", "2,2", "3,3", "4,4"})
    void shouldMatchHigherSingleEvidenceScore(ArgumentsAccessor argumentsAccessor) {
        var strength = argumentsAccessor.getInteger(0);
        var validity = argumentsAccessor.getInteger(1);
        var evidence = new Gpg45Scores.Evidence(strength, validity);
        var scoresToTest = new Gpg45Scores(evidence, 3, 2, 2);

        // L1C requires evidence with strength and validity scores of 1
        assertTrue(Gpg45Profile.L1C.isSatisfiedBy(scoresToTest));
    }

    @ParameterizedTest
    @ValueSource(ints = {1, 2, 3, 4})
    void shouldMatchHigherActivityScore(int activityScore) {
        // L1A requires activity score of 0
        assertTrue(Gpg45Profile.L1A.isSatisfiedBy(new Gpg45Scores(EV_22, activityScore, 1, 1)));
    }

    @ParameterizedTest
    @ValueSource(ints = {2, 3, 4})
    void shouldMatchHigherFraudScore(int fraudScore) {
        // L1A requires fraud score of 1
        assertTrue(Gpg45Profile.L1A.isSatisfiedBy(new Gpg45Scores(EV_22, 0, fraudScore, 1)));
    }

    @ParameterizedTest
    @ValueSource(ints = {2, 3, 4})
    void shouldMatchHigherVerificationScore(int verificationScore) {
        // L1A requires verification score of 1
        assertTrue(Gpg45Profile.L1A.isSatisfiedBy(new Gpg45Scores(EV_22, 0, 1, verificationScore)));
    }

    @Test
    void shouldMatchExtraEvidence() {
        // L1A requires only one piece of evidence
        Gpg45Scores target = new Gpg45Scores(EV_22, EV_11, 0, 1, 1);
        assertTrue(Gpg45Profile.L1A.isSatisfiedBy(target));
    }

    @Test
    void shouldNotMatchLower() {
        assertFalse(Gpg45Profile.V1C.isSatisfiedBy(new Gpg45Scores(EV_43, 1, 1, 3)));
        assertFalse(Gpg45Profile.V1C.isSatisfiedBy(new Gpg45Scores(EV_43, 1, 0, 4)));
        assertFalse(Gpg45Profile.V1C.isSatisfiedBy(new Gpg45Scores(EV_43, 0, 1, 4)));
        assertFalse(Gpg45Profile.V1C.isSatisfiedBy(new Gpg45Scores(EV_42, 1, 1, 4)));
        assertFalse(Gpg45Profile.V1C.isSatisfiedBy(new Gpg45Scores(EV_33, 1, 1, 4)));
        assertFalse(Gpg45Profile.V1C.isSatisfiedBy(new Gpg45Scores(EV_32, 0, 0, 3)));
    }

    @Test
    void shouldNotMatchMissingEvidence() {
        assertFalse(Gpg45Profile.V2A.isSatisfiedBy(new Gpg45Scores(EV_33, 3, 2, 3)));
    }

    @Test
    void shouldFindDifference() {
        assertEquals(
                new Gpg45Scores(-2, -2, -2, -1, -3),
                Gpg45Profile.H1B.difference(new Gpg45Scores(EV_11, 0, 0, 0)));
        assertEquals(
                new Gpg45Scores(0, 0, 0, 0, 0),
                Gpg45Profile.H1B.difference(new Gpg45Scores(EV_33, 2, 1, 3)));
        assertEquals(
                new Gpg45Scores(1, 1, 1, 1, 1),
                Gpg45Profile.H1B.difference(new Gpg45Scores(EV_44, 3, 2, 4)));
    }

    @Test
    void testAllPossibleCombinations() {
        assertDoesNotThrow(
                () -> {
                    int verificationMax = 4;
                    int fraudMax = 3;
                    int activityMax = 4;
                    int validityMax = 4;
                    int strengthMax = 4;

                    Map<String, List<Gpg45Profile>> profileMap = new HashMap<>();

                    System.out.println("Map build");
                    var t0 = System.currentTimeMillis();

                    for (int verification = 0; verification <= verificationMax; verification++) {
                        for (int fraud = 0; fraud <= fraudMax; fraud++) {
                            for (int activity = 0; activity <= activityMax; activity++) {
                                List<Gpg45Scores.Evidence> evidences = new ArrayList<>();
                                for (int doc = 0; doc < 3; doc++) {
                                    evidences.add(new Gpg45Scores.Evidence(0, 0));
                                    for (int validity = 0; validity <= validityMax; validity++) {
                                        for (int strength = 0;
                                                strength <= strengthMax;
                                                strength++) {
                                            var evidence =
                                                    new Gpg45Scores.Evidence(strength, validity);
                                            evidences.set(doc, evidence);
                                            var scores =
                                                    new Gpg45Scores(
                                                            evidences,
                                                            activity,
                                                            fraud,
                                                            verification);
                                            System.out.println(scores);
                                            var matches = new ArrayList<Gpg45Profile>();
                                            for (Gpg45Profile profile : Gpg45Profile.values()) {
                                                if (profile.isSatisfiedBy(scores)) {
                                                    matches.add(profile);
                                                    System.out.println(profile.code());
                                                }
                                            }
                                            if (matches.size() == 0) {
                                                System.out.println("NONE");
                                            }
                                            profileMap.put(scores.toString(), matches);
                                        }
                                    }
                                }
                            }
                        }
                    }
                    var t1 = System.currentTimeMillis();
                    System.out.println("T:" + (t1 - t0));
                    System.out.println("Map lookup");
                    var profiles = profileMap.get("[[22], 3, 1, 3]");
                    for (Gpg45Profile profile : profiles) {
                        System.out.println(profile.label);
                    }
                    var t2 = System.currentTimeMillis();
                    System.out.println("T:" + (t2 - t1));
                });
    }
}
