package uk.gov.di.ipv.core.library.helpers;

import java.util.Objects;
import java.util.regex.Pattern;

public class ValidationHelper {
    private static final Pattern IPV_JOURNEY_ID_PATTERN = Pattern.compile("^[A-Za-z0-9_-]{43}$");
    private static final Pattern GOVUK_SIGNING_JOURNEY_ID =
            Pattern.compile(
                    "^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$");

    private ValidationHelper() {
        // prevent initialisation
    }

    public static boolean isValidIpvSessionId(String id) {
        if (Objects.isNull(id)) {
            return false;
        }
        return IPV_JOURNEY_ID_PATTERN.matcher(id).matches();
    }

    public static boolean isValidGovukSigningJourneyId(String id) {
        if (Objects.isNull(id)) {
            return false;
        }
        return GOVUK_SIGNING_JOURNEY_ID.matcher(id).matches();
    }
}
