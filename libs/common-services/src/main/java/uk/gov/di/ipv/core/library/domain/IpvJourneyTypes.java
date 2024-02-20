package uk.gov.di.ipv.core.library.domain;

import lombok.Getter;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@Getter
@ExcludeFromGeneratedCoverageReport
public enum IpvJourneyTypes {
    // TODO: PYIC-4459 Delete this once no active sessions are using it
    IPV_CORE_MAIN_JOURNEY("ipv-core-main-journey"),

    // Main entry point
    INITIAL_JOURNEY_SELECTION("initial-journey-selection"),

    // Successful journeys
    REUSE_EXISTING_IDENTITY("reuse-existing-identity"),
    NEW_P2_IDENTITY("new-p2-identity"),

    // Unsuccessful journeys
    INELIGIBLE("ineligible"),
    FAILED("failed"),
    TECHNICAL_ERROR("technical-error"),
    SESSION_TIMEOUT("session-timeout"),

    // F2F return journeys
    F2F_PENDING("f2f-pending"),
    F2F_FAILED("f2f-failed"),

    // Operational profile journeys
    OPERATIONAL_PROFILE_MIGRATION("operational-profile-migration"),
    OPERATIONAL_PROFILE_REUSE("operational-profile-reuse");

    private final String path;

    IpvJourneyTypes(String path) {
        this.path = path;
    }
}
