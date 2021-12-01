package uk.gov.di.ipv.domain;

public class CredentialIssuerException extends RuntimeException {

    private ErrorResponse errorResponse;

    private int httpStatusCode;

    public CredentialIssuerException(int httpStatusCode, ErrorResponse errorResponse) {
        this.errorResponse = errorResponse;
        this.httpStatusCode = httpStatusCode;
    }

    public ErrorResponse getErrorResponse() {
        return errorResponse;
    }

    public int getHttpStatusCode() {
        return httpStatusCode;
    }
}
