package uk.gov.di.ipv.core.statemachine;

public class UnknownEventException extends Throwable {

    public UnknownEventException() {
        super();
    }

    public UnknownEventException(String message) {
        super(message);
    }

    public UnknownEventException(String message, Throwable cause) {
        super(message, cause);
    }

    public UnknownEventException(Throwable cause) {
        super(cause);
    }
}
