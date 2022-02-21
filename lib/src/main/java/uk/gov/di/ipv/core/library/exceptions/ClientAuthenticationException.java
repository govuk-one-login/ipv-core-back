package uk.gov.di.ipv.core.library.exceptions;

public class ClientAuthenticationException extends Exception {
    public ClientAuthenticationException(String message) {
        super(message);
    }

    public ClientAuthenticationException(Throwable e) {
        super(e);
    }
}
