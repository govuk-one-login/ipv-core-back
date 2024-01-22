package uk.gov.di.ipv.core.library.domain;

import lombok.Getter;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@Getter
@ExcludeFromGeneratedCoverageReport
public enum IpvJourneyTypes {
    IPV_CORE_MAIN_JOURNEY("ipv-core-main-journey"),
    TECHNICAL_ERROR("technical-error");

    private final String path;

    IpvJourneyTypes(String path) {
        this.path = path;
    }
}
