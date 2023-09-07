package uk.gov.di.ipv.core.library.domain;

import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@ExcludeFromGeneratedCoverageReport
public enum IpvJourneyTypes {
    IPV_CORE_MAIN_JOURNEY("ipv-core-main-journey");

    private final String value;

    IpvJourneyTypes(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}
