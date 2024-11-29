package uk.gov.di.ipv.core.library.domain;

import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@ExcludeFromGeneratedCoverageReport
public enum ReverificationFailureCode {
    NO_IDENTITY_AVAILABLE("no_identity_available", "No existing identity available."),
    IDENTITY_CHECK_INCOMPLETE("identity_check_incomplete", "Unable to complete identity check."),
    IDENTITY_CHECK_FAILED("identity_check_failed", "Identity check failed."),
    IDENTITY_DID_NOT_MATCH("identity_did_not_match", "Failed to match identity.");

    private final String failureCode;
    private final String failureDescription;

    ReverificationFailureCode(String failureCode, String failureDescription) {
        this.failureCode = failureCode;
        this.failureDescription = failureDescription;
    }

    public String getFailureCode() {
        return failureCode;
    }

    public String getFailureDescription() {
        return failureDescription;
    }
}
