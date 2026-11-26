package uk.gov.di.ipv.core.storetriagedata.exceptions;

import uk.gov.di.ipv.core.library.domain.ErrorResponse;

public class InvalidTriageDataException extends Exception {
    private final ErrorResponse errorResponse;

    public InvalidTriageDataException(ErrorResponse errorResponse, String detail) {
        super(detail);
        this.errorResponse = errorResponse;
    }

    public ErrorResponse getErrorResponse() {
        return errorResponse;
    }
}
