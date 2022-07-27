package uk.gov.di.ipv.core.evaluategpg45scores.gpg45;

import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static uk.gov.di.ipv.core.evaluategpg45scores.gpg45.Gpg45Scores.EV_11;
import static uk.gov.di.ipv.core.evaluategpg45scores.gpg45.Gpg45Scores.EV_22;
import static uk.gov.di.ipv.core.evaluategpg45scores.gpg45.Gpg45Scores.EV_32;
import static uk.gov.di.ipv.core.evaluategpg45scores.gpg45.Gpg45Scores.EV_33;
import static uk.gov.di.ipv.core.evaluategpg45scores.gpg45.Gpg45Scores.EV_42;
import static uk.gov.di.ipv.core.evaluategpg45scores.gpg45.Gpg45Scores.EV_43;
import static uk.gov.di.ipv.core.evaluategpg45scores.gpg45.Gpg45Scores.EV_44;

public class Gpg45ProfileTest {

    @Test
    public void shouldMatchExact() {
        for (Gpg45Profile profile : Gpg45Profile.values()) {
            assertTrue(profile.satisfiedBy(profile.getScores()));
        }
    }

    @Test
    public void shouldMatchHigher() {
        assertTrue(Gpg45Profile.L1A.satisfiedBy(new Gpg45Scores(EV_22, 0, 1, 2)));
        assertTrue(Gpg45Profile.L1A.satisfiedBy(new Gpg45Scores(EV_32, 1, 1, 1)));
        assertTrue(Gpg45Profile.L1A.satisfiedBy(new Gpg45Scores(EV_33, 0, 1, 1)));
        assertTrue(Gpg45Profile.L1A.satisfiedBy(new Gpg45Scores(EV_22, 1, 1, 1)));
        assertTrue(Gpg45Profile.L1A.satisfiedBy(new Gpg45Scores(EV_22, 1, 2, 1)));
        assertTrue(Gpg45Profile.L1A.satisfiedBy(new Gpg45Scores(EV_44, 4, 4, 4)));
        assertTrue(Gpg45Profile.L1A.satisfiedBy(new Gpg45Scores(EV_22, EV_11, 0, 1, 2)));
    }

    @Test
    public void shouldMatchExtraEvidence() {
        Gpg45Scores target = new Gpg45Scores(EV_22, EV_11, 0, 1, 1);
        assertTrue(Gpg45Profile.L1A.satisfiedBy(target));
    }

    @Test
    public void shouldNotMatchLower() {
        assertFalse(Gpg45Profile.V1C.satisfiedBy(new Gpg45Scores(EV_43, 1, 1, 3)));
        assertFalse(Gpg45Profile.V1C.satisfiedBy(new Gpg45Scores(EV_43, 1, 0, 4)));
        assertFalse(Gpg45Profile.V1C.satisfiedBy(new Gpg45Scores(EV_43, 0, 1, 4)));
        assertFalse(Gpg45Profile.V1C.satisfiedBy(new Gpg45Scores(EV_42, 1, 1, 4)));
        assertFalse(Gpg45Profile.V1C.satisfiedBy(new Gpg45Scores(EV_33, 1, 1, 4)));
        assertFalse(Gpg45Profile.V1C.satisfiedBy(new Gpg45Scores(EV_32, 0, 0, 3)));
    }

    @Test
    public void shouldNotMatchMissingEvidence() {
        assertFalse(Gpg45Profile.V2A.satisfiedBy(new Gpg45Scores(EV_33, 3, 2, 3)));
    }

    @Test
    public void shouldFindDifference() {
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
    public void testAllPossibleCombinations() {
        int verificationMax = 4;
        int fraudMax = 3;
        int activityMax = 4;
        int validityMax = 4;
        int strengthMax = 4;

        // IntStream.range(0, verificationMax+1).forEach(i ->System.out.println(i));

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
                            for (int strength = 0; strength <= strengthMax; strength++) {
                                var evidence = new Gpg45Scores.Evidence(strength, validity);
                                evidences.set(doc, evidence);
                                var scores =
                                        new Gpg45Scores(evidences, activity, fraud, verification);
                                System.out.println(scores);
                                var matches = new ArrayList<Gpg45Profile>();
                                for (Gpg45Profile profile : Gpg45Profile.values()) {
                                    if (profile.satisfiedBy(scores)) {
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
    }
}
