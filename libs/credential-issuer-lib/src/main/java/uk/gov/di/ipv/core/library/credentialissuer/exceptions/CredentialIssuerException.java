package uk.gov.di.ipv.core.library.credentialissuer.exceptions;

import uk.gov.di.ipv.core.library.domain.ErrorResponse;

public class CredentialIssuerException extends RuntimeException {

    private final ErrorResponse errorResponse;

    private final int httpStatusCode;

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
