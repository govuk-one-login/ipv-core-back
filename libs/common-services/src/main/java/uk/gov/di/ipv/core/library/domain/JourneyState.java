package uk.gov.di.ipv.core.library.domain;

public record JourneyState(IpvJourneyTypes subJourney, String state) {
    public static final String JOURNEY_STATE_DELIMITER = "/";

    public JourneyState(String sessionItemString) {
        this(
                IpvJourneyTypes.valueOf(splitSessionItemString(sessionItemString)[0]),
                splitSessionItemString(sessionItemString)[1]);
    }

    public String toSessionItemString() {
        return String.format("%s%s%s", subJourney, JOURNEY_STATE_DELIMITER, state);
    }

    private static String[] splitSessionItemString(String sessionItemString) {
        return sessionItemString.split(JOURNEY_STATE_DELIMITER, 2);
    }
}
