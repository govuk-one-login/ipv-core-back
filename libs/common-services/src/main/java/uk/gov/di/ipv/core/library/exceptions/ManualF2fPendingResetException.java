package uk.gov.di.ipv.core.library.exceptions;

public class ManualF2fPendingResetException extends RuntimeException {
    public ManualF2fPendingResetException(String message) {
        super(message);
    }

    public ManualF2fPendingResetException(String message, Throwable cause) {
        super(message, cause);
    }
}
