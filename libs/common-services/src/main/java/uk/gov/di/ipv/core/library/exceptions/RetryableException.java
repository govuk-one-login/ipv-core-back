package uk.gov.di.ipv.core.library.exceptions;

public class RetryableException extends Exception {

    public RetryableException(String message) {
        super(message);
    }

    public RetryableException(Exception e) {
        super(e);
    }
}
