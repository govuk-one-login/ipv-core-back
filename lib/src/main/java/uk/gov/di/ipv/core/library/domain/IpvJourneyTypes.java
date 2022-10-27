package uk.gov.di.ipv.core.library.domain;

public enum IpvJourneyTypes {
    IPV_CORE_MAIN_JOURNEY("ipv-core-main-journey"),
    MITIGATION_JOURNEY_MJ01("mj01");

    private final String value;

    IpvJourneyTypes(String value) {
        this.value = value;
    }

    public String getValue() {
        return value;
    }
}
