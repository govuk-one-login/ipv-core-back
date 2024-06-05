package uk.gov.di.ipv.core.library.exceptions;

public class UnknownAccessTokenException extends Exception {
    public UnknownAccessTokenException(String errorMessage) {
        super(errorMessage);
    }
}
