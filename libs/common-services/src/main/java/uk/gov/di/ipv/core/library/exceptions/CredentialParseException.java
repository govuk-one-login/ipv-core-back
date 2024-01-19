package uk.gov.di.ipv.core.library.exceptions;

public class CredentialParseException extends Exception {
    public CredentialParseException(String message) {
        super(message);
    }

    public CredentialParseException(String message, Throwable cause) {
        super(message, cause);
    }
}
