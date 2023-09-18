package uk.gov.di.ipv.core.library.exceptions;

public class NoConfigForConnectionException extends RuntimeException {
    public NoConfigForConnectionException(String message) {
        super(message);
    }
}
