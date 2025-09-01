package uk.gov.di.ipv.core.library.domain;

import lombok.Getter;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@Getter
@ExcludeFromGeneratedCoverageReport
public enum IpvJourneyTypes {
    // Making changes to this enum? Let the data team know. Changes here will cause changes to the
    // IPV_SUBJOURNEY_START audit event, which they consume

    // Main entry point
    INITIAL_JOURNEY_SELECTION("initial-journey-selection"),

    // Successful journeys
    REUSE_EXISTING_IDENTITY("reuse-existing-identity"),
    NEW_P1_IDENTITY("new-p1-identity"),
    NEW_P2_IDENTITY("new-p2-identity"),
    REPEAT_FRAUD_CHECK("repeat-fraud-check"),

    // Unsuccessful journeys
    INELIGIBLE("ineligible"),
    FAILED("failed"),
    TECHNICAL_ERROR("technical-error"),
    SESSION_TIMEOUT("session-timeout"),

    // F2F journeys
    F2F_HAND_OFF("f2f-hand-off"),
    F2F_PENDING("f2f-pending"),
    F2F_FAILED("f2f-failed"),

    // Continuity of Identity journeys
    UPDATE_ADDRESS("update-address"),
    UPDATE_NAME("update-name"),

    // MFA reset journey
    REVERIFICATION("reverification");

    private final String path;

    IpvJourneyTypes(String path) {
        this.path = path;
    }
}
