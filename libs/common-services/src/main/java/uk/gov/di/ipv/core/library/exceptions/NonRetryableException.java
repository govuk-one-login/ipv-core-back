package uk.gov.di.ipv.core.library.exceptions;

public class NonRetryableException extends Exception {

    public NonRetryableException() {
        super();
    }

    public NonRetryableException(Exception e) {
        super(e);
    }

    public NonRetryableException(String msg) {
        super(msg);
    }
}
