package uk.gov.di.ipv.core.processjourneyevent.statemachine.exceptions;

public class MissingSecurityCheckCredential extends Exception {
    public MissingSecurityCheckCredential() {
        super();
    }

    public MissingSecurityCheckCredential(String message) {
        super(message);
    }
}
