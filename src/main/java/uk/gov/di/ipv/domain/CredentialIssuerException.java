package uk.gov.di.ipv.domain;

public class CredentialIssuerException extends RuntimeException{

    public CredentialIssuerException() {
    }

    public CredentialIssuerException(String message) {
        super(message);
    }

    public CredentialIssuerException(String message, Throwable cause) {
        super(message, cause);
    }

    public CredentialIssuerException(Throwable cause) {
        super(cause);
    }
}
