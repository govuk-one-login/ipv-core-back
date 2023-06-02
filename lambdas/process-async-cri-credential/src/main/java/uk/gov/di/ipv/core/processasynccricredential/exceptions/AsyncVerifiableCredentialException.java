package uk.gov.di.ipv.core.processasynccricredential.exceptions;

import uk.gov.di.ipv.core.library.domain.ErrorResponse;

public class AsyncVerifiableCredentialException extends RuntimeException {
    private final ErrorResponse errorResponse;

    public AsyncVerifiableCredentialException(ErrorResponse errorResponse) {
        this.errorResponse = errorResponse;
    }

    public ErrorResponse getErrorResponse() {
        return errorResponse;
    }
}
