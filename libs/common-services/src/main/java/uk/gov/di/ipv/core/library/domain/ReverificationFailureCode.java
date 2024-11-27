package uk.gov.di.ipv.core.library.domain;

import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@ExcludeFromGeneratedCoverageReport
public enum ReverificationFailureCode {
    NO_IDENTITY_AVAILABLE("no_identity_available"),
    IDENTITY_CHECK_INCOMPLETE("identity_check_incomplete"),
    IDENTITY_CHECK_FAILED("identity_check_failed"),
    IDENTITY_DID_NOT_MATCH("identity_did_not_match");

    private final String failureCode;

    ReverificationFailureCode(String failureCode) {
        this.failureCode = failureCode;
    }

    public String getFailureCode() {
        return failureCode;
    }
}
