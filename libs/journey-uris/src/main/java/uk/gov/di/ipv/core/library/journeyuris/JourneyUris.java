package uk.gov.di.ipv.core.library.journeyuris;

@java.lang.SuppressWarnings("java:S1075")
public class JourneyUris {
    private JourneyUris() {
        throw new IllegalStateException("Utility class");
    }

    public static final String JOURNEY_ACCESS_DENIED_PATH = "/journey/access-denied";
    public static final String JOURNEY_ACCESS_TOKEN_PATH = "/journey/cri/access-token";
    public static final String JOURNEY_END_PATH = "/journey/end";
    public static final String JOURNEY_ERROR_PATH = "/journey/error";
    public static final String JOURNEY_EVALUATE_PATH = "/journey/evaluate";
    public static final String JOURNEY_FAIL_PATH = "/journey/fail";
    public static final String JOURNEY_FAIL_WITH_NO_CI_PATH = "/journey/fail-with-no-ci";
    public static final String JOURNEY_NEXT_PATH = "/journey/next";
    public static final String JOURNEY_PENDING_PATH = "/journey/pending";
    public static final String JOURNEY_PYI_KBV_FAIL_PATH = "/journey/pyi-kbv-fail";
    public static final String JOURNEY_PYI_NO_MATCH_PATH = "/journey/pyi-no-match";
    public static final String JOURNEY_RESET_IDENTITY_PATH = "/journey/reset-identity";
    public static final String JOURNEY_REUSE_PATH = "/journey/reuse";
    public static final String JOURNEY_TEMPORARILY_UNAVAILABLE_PATH =
            "/journey/temporarily-unavailable";
}
