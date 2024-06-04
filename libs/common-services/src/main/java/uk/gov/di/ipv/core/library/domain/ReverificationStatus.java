package uk.gov.di.ipv.core.library.domain;

import lombok.Getter;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@Getter
@ExcludeFromGeneratedCoverageReport
public enum ReverificationStatus {
    SUCCESS("success"),
    FAILED("failed");

    private final String status;

    ReverificationStatus(String status) {
        this.status = status;
    }
    ;
}
