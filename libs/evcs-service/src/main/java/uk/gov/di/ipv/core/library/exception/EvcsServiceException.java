package uk.gov.di.ipv.core.library.exception;

import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.exceptions.ErrorResponseException;

public class EvcsServiceException extends Exception implements ErrorResponseException {
    private final ErrorResponse errorResponse;

    private final int responseCode;

    public EvcsServiceException(int responseCode, ErrorResponse errorResponse) {
        super(errorResponse.getMessage());
        this.errorResponse = errorResponse;
        this.responseCode = responseCode;
    }

    public ErrorResponse getErrorResponse() {
        return errorResponse;
    }

    @Override
    public String getErrorReason() {
        return this.errorResponse.getMessage();
    }

    @Override
    public int getResponseCode() {
        return responseCode;
    }
}
