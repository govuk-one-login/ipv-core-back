package uk.gov.di.ipv.core.library.cimit.exception;

public class CiRetrievalException extends Exception {
    public CiRetrievalException(String message) {
        super(message);
    }

    public CiRetrievalException(String message, Throwable e) {
        super(message, e);
    }
}
