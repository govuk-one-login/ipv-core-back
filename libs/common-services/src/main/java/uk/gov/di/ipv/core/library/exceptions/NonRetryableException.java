package uk.gov.di.ipv.core.library.exceptions;

public class NonRetryableException extends Exception {

    public NonRetryableException(Exception e) {
        super(e);
    }

    public NonRetryableException(String msg) {
        super(msg);
    }

    public NonRetryableException(String msg, Exception e) {
        super(msg, e);
    }
}
