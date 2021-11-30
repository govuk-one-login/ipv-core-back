package uk.gov.di.ipv.domain;

public class CredentialIssuerException extends RuntimeException{

    public CredentialIssuerException(String message) {
        super(message);
    }

    public CredentialIssuerException(Throwable cause) {
        super(cause);
    }
}
