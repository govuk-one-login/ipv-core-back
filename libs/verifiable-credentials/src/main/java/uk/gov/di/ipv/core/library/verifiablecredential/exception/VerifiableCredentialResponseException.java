package uk.gov.di.ipv.core.library.verifiablecredential.exception;

import uk.gov.di.ipv.core.library.domain.ErrorResponse;

public class VerifiableCredentialResponseException extends RuntimeException {

    private final ErrorResponse errorResponse;

    private final int httpStatusCode;

    public VerifiableCredentialResponseException(int httpStatusCode, ErrorResponse errorResponse) {
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
