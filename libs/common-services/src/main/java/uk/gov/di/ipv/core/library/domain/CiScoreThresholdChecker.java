package uk.gov.di.ipv.core.library.domain;

public class CiScoreThresholdChecker {
    private CiScoreThresholdChecker() {
        throw new IllegalStateException("Utility class");
    }

    public static boolean ciScoreBreachesThreshold(int ciScore, String threshold) {
        return ciScore > Integer.parseInt(threshold);
    }
}
