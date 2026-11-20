package uk.gov.di.ipv.core.library.cimit.exception;

public class CimitHttpRequestException extends Exception {
    public CimitHttpRequestException(String message, Exception e) {
        super(message, e);
    }
}
