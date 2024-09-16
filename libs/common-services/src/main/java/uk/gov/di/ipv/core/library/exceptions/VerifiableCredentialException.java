package uk.gov.di.ipv.core.library.exceptions;

import uk.gov.di.ipv.core.library.domain.ErrorResponse;

public class VerifiableCredentialException extends Exception implements ErrorResponseException {

    private final ErrorResponse errorResponse;

    private final int responseCode;

    public VerifiableCredentialException(int responseCode, ErrorResponse errorResponse) {
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
