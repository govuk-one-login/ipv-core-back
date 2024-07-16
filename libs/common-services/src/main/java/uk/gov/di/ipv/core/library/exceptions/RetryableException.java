package uk.gov.di.ipv.core.library.exceptions;

public class RetryableException extends Exception {

    public RetryableException(Exception e) {
        super(e);
    }
}
