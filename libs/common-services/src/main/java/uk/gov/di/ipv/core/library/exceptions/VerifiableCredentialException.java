package uk.gov.di.ipv.core.library.exceptions;

import uk.gov.di.ipv.core.library.domain.ErrorResponse;

// Should not extend runtime exception?
public class VerifiableCredentialException extends RuntimeException {

    private final ErrorResponse errorResponse;

    private final int httpStatusCode;

    public VerifiableCredentialException(int httpStatusCode, ErrorResponse errorResponse) {
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
