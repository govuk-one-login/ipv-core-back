package uk.gov.di.ipv.core.library.journeys;

import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

public class Events {
    @ExcludeFromGeneratedCoverageReport
    private Events() {
        throw new IllegalStateException("String constants class");
    }

    // This event is a special value that is caught explicitly by the journey event handler
    public static final String BUILD_CLIENT_OAUTH_RESPONSE_EVENT = "build-client-oauth-response";
    public static final String PROBLEM_DIFFERENT_BROWSER_PAGE_EVENT = "problem-different-browser";

    public static final String ENHANCED_VERIFICATION_EVENT = "enhanced-verification";
    public static final String ALTERNATE_DOC_INVALID_DL_EVENT = "alternate-doc-invalid-dl";
    public static final String ALTERNATE_DOC_INVALID_PASSPORT_EVENT =
            "alternate-doc-invalid-passport";
    public static final String FAIL_WITH_CI_EVENT = "fail-with-ci";
}
