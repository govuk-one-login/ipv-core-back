package uk.gov.di.ipv.core.library.helpers;

public class NumberHelper {

    private NumberHelper() {
        // prevent initialisation
    }

    public static int parseIntOrDefault(String value, int defaultVal) {
        try {
            return value != null ? Integer.parseInt(value) : defaultVal;
        } catch (NumberFormatException e) {
            return defaultVal;
        }
    }
}
