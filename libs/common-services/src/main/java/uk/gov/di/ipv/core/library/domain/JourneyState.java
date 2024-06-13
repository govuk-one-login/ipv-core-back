package uk.gov.di.ipv.core.library.domain;

public record JourneyState(IpvJourneyTypes subJourney, String state) {
    public static final String JOURNEY_STATE_DELIMITER = "/";
}
