package uk.gov.di.ipv.core.library.domain;

import lombok.Getter;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@Getter
@ExcludeFromGeneratedCoverageReport
public enum IpvJourneyTypes {
    IPV_CORE_MAIN_JOURNEY("ipv-core-main-journey"),
    INELIGIBLE("ineligible"),
    FAILED("failed"),
    TECHNICAL_ERROR("technical-error"),
    F2F_PENDING("f2f-pending"),
    F2F_FAILED("f2f-failed"),
    OPERATIONAL_PROFILE_MIGRATION("operational-profile-migration"),
    OPERATIONAL_PROFILE_REUSE("operational-profile-reuse");

    private final String path;

    IpvJourneyTypes(String path) {
        this.path = path;
    }
}
