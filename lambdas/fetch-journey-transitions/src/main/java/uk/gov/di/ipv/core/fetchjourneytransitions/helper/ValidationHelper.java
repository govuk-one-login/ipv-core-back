package uk.gov.di.ipv.core.fetchjourneytransitions.helper;

import java.util.UUID;
import java.util.regex.Pattern;

public class ValidationHelper {

    private static final Pattern IPV_JOURNEY_ID_PATTERN = Pattern.compile("^[A-Za-z0-9_-]{43}$");

    public static int parseIntOrDefault(String value, int defaultVal) {
        try {
            return value != null ? Integer.parseInt(value) : defaultVal;
        } catch (NumberFormatException e) {
            return defaultVal;
        }
    }

    public static boolean isValidIpvSessionId(String id) {
        return IPV_JOURNEY_ID_PATTERN.matcher(id).matches();
    }

    public static boolean isValidUUIDv4(String id) {
        try {
            UUID uuid = UUID.fromString(id);
            return uuid.version() == 4;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }
}
