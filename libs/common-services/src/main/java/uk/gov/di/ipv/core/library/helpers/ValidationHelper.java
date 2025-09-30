package uk.gov.di.ipv.core.library.helpers;

import java.util.Objects;
import java.util.regex.Pattern;

public class ValidationHelper {
    private static final Pattern IPV_SESSION_ID_PATTERN = Pattern.compile("^[A-Za-z0-9_-]{43}$");

    private ValidationHelper() {
        // prevent initialisation
    }

    public static boolean isValidIpvSessionId(String id) {
        if (Objects.isNull(id)) {
            return false;
        }
        return IPV_SESSION_ID_PATTERN.matcher(id).matches();
    }
}
