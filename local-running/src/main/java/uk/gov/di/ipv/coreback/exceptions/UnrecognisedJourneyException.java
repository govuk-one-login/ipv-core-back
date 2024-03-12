package uk.gov.di.ipv.coreback.exceptions;

public class UnrecognisedJourneyException extends RuntimeException {
    public UnrecognisedJourneyException(String message) {
        super(message);
    }
}
