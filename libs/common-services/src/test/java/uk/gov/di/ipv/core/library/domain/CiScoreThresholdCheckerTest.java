package uk.gov.di.ipv.core.library.domain;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static uk.gov.di.ipv.core.library.domain.CiScoreThresholdChecker.ciScoreBreachesThreshold;

class CiScoreThresholdCheckerTest {
    @Test
    void ciScoreBreachesThresholdShouldReturnTrueIfScoreAboveThreshold() {
        assertTrue(ciScoreBreachesThreshold(101, "100"));
    }

    @Test
    void ciScoreBreachesThresholdShouldReturnFalseIfScoreEqualsThreshold() {
        assertFalse(ciScoreBreachesThreshold(100, "100"));
    }

    @Test
    void ciScoreBreachesThresholdShouldReturnFalseIfScoreBelowThreshold() {
        assertFalse(ciScoreBreachesThreshold(99, "100"));
    }
}
