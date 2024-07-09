package uk.gov.di.ipv.core.library.exceptions;

public class RetryException extends Exception {
    public RetryException(Exception e) {
        super(e);
    }

    public RetryException(String msg) {
        super(msg);
    }
}
