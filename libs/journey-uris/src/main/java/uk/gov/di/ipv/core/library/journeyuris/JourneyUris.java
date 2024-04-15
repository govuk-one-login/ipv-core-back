package uk.gov.di.ipv.core.library.journeyuris;

@java.lang.SuppressWarnings("java:S1075")
public class JourneyUris {
    private JourneyUris() {
        throw new IllegalStateException("Utility class");
    }

    public static final String JOURNEY_ACCESS_DENIED_PATH = "/journey/access-denied";
    public static final String JOURNEY_ERROR_PATH = "/journey/error";
    public static final String JOURNEY_F2F_FAIL_PATH = "/journey/f2f-fail";
    public static final String JOURNEY_ENHANCED_VERIFICATION_F2F_FAIL_PATH =
            "/journey/enhanced-verification-f2f-fail";
    public static final String JOURNEY_ENHANCED_VERIFICATION_PATH =
            "/journey/enhanced-verification";
    public static final String JOURNEY_FAIL_WITH_CI_PATH = "/journey/fail-with-ci";
    public static final String JOURNEY_FAIL_WITH_CI_AND_FORCED_RESET_PATH =
            "/journey/fail-with-ci-and-forced-reset";
    public static final String JOURNEY_FAIL_WITH_NO_CI_PATH = "/journey/fail-with-no-ci";
    public static final String JOURNEY_IDENTITY_STORED_PATH = "/journey/identity-stored";
    public static final String JOURNEY_IN_MIGRATION_REUSE_PATH = "/journey/in-migration-reuse";
    public static final String JOURNEY_IPV_GPG45_MEDIUM_PATH = "/journey/ipv-gpg45-medium";
    public static final String JOURNEY_OPERATIONAL_PROFILE_REUSE_PATH =
            "/journey/operational-profile-reuse";
    public static final String JOURNEY_MET_PATH = "/journey/met";
    public static final String JOURNEY_NEXT_PATH = "/journey/next";
    public static final String JOURNEY_VCS_NOT_CORRELATED = "/journey/vcs-not-correlated";
    public static final String JOURNEY_NOT_FOUND_PATH = "/journey/not-found";
    public static final String JOURNEY_PENDING_PATH = "/journey/pending";
    public static final String JOURNEY_RESET_IDENTITY_PATH = "/journey/reset-identity";
    public static final String JOURNEY_RESET_GPG45_IDENTITY_PATH = "/journey/reset-gpg45-identity";
    public static final String JOURNEY_REUSE_PATH = "/journey/reuse";
    public static final String JOURNEY_TEMPORARILY_UNAVAILABLE_PATH =
            "/journey/temporarily-unavailable";
    public static final String JOURNEY_UNMET_PATH = "/journey/unmet";
    public static final String JOURNEY_ALTERNATE_DOC_PATH = "/journey/alternate-doc";
    public static final String JOURNEY_ALTERNATE_DOC_INVALID_DL_PATH =
            JOURNEY_ALTERNATE_DOC_PATH + "-invalid-dl";
    public static final String JOURNEY_REPEAT_FRAUD_CHECK_PATH = "/journey/repeat-fraud-check";
}
