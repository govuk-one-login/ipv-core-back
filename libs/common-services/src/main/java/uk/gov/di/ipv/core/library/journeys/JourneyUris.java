package uk.gov.di.ipv.core.library.journeys;

import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@java.lang.SuppressWarnings("java:S1075")
public class JourneyUris {
    @ExcludeFromGeneratedCoverageReport
    private JourneyUris() {
        throw new IllegalStateException("Utility class");
    }

    public static final String JOURNEY_ACCESS_DENIED_PATH = "/journey/access-denied";
    // This journey is a special value that is caught explicitly by the journey event handler
    public static final String JOURNEY_BUILD_CLIENT_OAUTH_RESPONSE_PATH =
            "/journey/" + Events.BUILD_CLIENT_OAUTH_RESPONSE_EVENT;
    public static final String JOURNEY_CALL_DCMAW_ASYNC_CRI_PATH = "/journey/call-dcmaw-async-cri";
    public static final String JOURNEY_CALL_TICF_CRI_PATH = "/journey/call-ticf-cri";
    public static final String JOURNEY_CHECK_COI_PATH = "/journey/check-coi";
    public static final String JOURNEY_CHECK_EXISTING_IDENTITY_PATH =
            "/journey/check-existing-identity";
    public static final String JOURNEY_CHECK_GPG45_SCORE_PATH = "/journey/check-gpg45-score";
    public static final String JOURNEY_COI_CHECK_FAILED_PATH = "/journey/coi-check-failed";
    public static final String JOURNEY_COI_CHECK_PASSED_PATH = "/journey/coi-check-passed";
    public static final String JOURNEY_DL_AUTH_SOURCE_CHECK_PATH = "/journey/dl-auth-source-check";
    public static final String JOURNEY_ENHANCED_VERIFICATION_F2F_FAIL_PATH =
            "/journey/enhanced-verification-f2f-fail";
    public static final String JOURNEY_ENHANCED_VERIFICATION_PATH =
            "/journey/enhanced-verification";
    public static final String JOURNEY_ERROR_PATH = "/journey/error";
    public static final String JOURNEY_EVALUATE_GPG45_SCORES_PATH =
            "/journey/evaluate-gpg45-scores";
    public static final String JOURNEY_F2F_FAIL_PATH = "/journey/f2f-fail";
    public static final String JOURNEY_FAIL_WITH_CI_PATH = "/journey/fail-with-ci";
    public static final String JOURNEY_FAIL_WITH_NO_CI_PATH = "/journey/fail-with-no-ci";
    public static final String JOURNEY_IDENTITY_STORED_PATH = "/journey/identity-stored";
    public static final String JOURNEY_IN_MIGRATION_REUSE_PATH = "/journey/in-migration-reuse";
    public static final String JOURNEY_INVALID_REQUEST_PATH = "/journey/invalid-request";
    public static final String JOURNEY_IPV_GPG45_LOW_PATH = "/journey/ipv-gpg45-low";
    public static final String JOURNEY_IPV_GPG45_MEDIUM_PATH = "/journey/ipv-gpg45-medium";
    public static final String JOURNEY_MET_PATH = "/journey/met";
    public static final String JOURNEY_NEXT_PATH = "/journey/next";
    public static final String JOURNEY_NOT_FOUND_PATH = "/journey/not-found";
    public static final String JOURNEY_OPERATIONAL_PROFILE_REUSE_PATH =
            "/journey/operational-profile-reuse";
    public static final String JOURNEY_PENDING_PATH = "/journey/pending";
    public static final String JOURNEY_REPEAT_FRAUD_CHECK_PATH = "/journey/repeat-fraud-check";
    public static final String JOURNEY_REPROVE_IDENTITY_GPG45_MEDIUM_PATH =
            "/journey/reprove-identity";
    public static final String JOURNEY_REPROVE_IDENTITY_GPG45_LOW_PATH =
            "/journey/reprove-identity-gpg45-low";
    public static final String JOURNEY_RESET_SESSION_IDENTITY_PATH =
            "/journey/reset-session-identity";
    public static final String JOURNEY_REUSE_PATH = "/journey/reuse";
    public static final String JOURNEY_REUSE_WITH_STORE_PATH = "/journey/reuse-with-store";
    public static final String JOURNEY_STORE_IDENTITY_PATH = "/journey/store-identity";
    public static final String JOURNEY_TEMPORARILY_UNAVAILABLE_PATH =
            "/journey/temporarily-unavailable";
    public static final String JOURNEY_UNMET_PATH = "/journey/unmet";
    public static final String JOURNEY_VCS_NOT_CORRELATED = "/journey/vcs-not-correlated";
    public static final String JOURNEY_ABANDON_PATH = "/journey/abandon";
    public static final String JOURNEY_DCMAW_ASYNC_VC_RECEIVED_PATH =
            "/journey/dcmaw-async-vc-received";
}
