package uk.gov.di.ipv.core.library.domain;

public class CredentialIssuerException extends RuntimeException {

    private final int httpStatusCode;

    public CredentialIssuerException(int httpStatusCode) {
        this.httpStatusCode = httpStatusCode;
    }

    public int getHttpStatusCode() {
        return httpStatusCode;
    }
}
