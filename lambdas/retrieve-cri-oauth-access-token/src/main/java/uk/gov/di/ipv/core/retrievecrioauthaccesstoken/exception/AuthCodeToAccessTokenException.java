package uk.gov.di.ipv.core.retrievecrioauthaccesstoken.exception;

import uk.gov.di.ipv.core.library.domain.ErrorResponse;

public class AuthCodeToAccessTokenException extends RuntimeException {

    private final ErrorResponse errorResponse;

    private final int httpStatusCode;

    public AuthCodeToAccessTokenException(int httpStatusCode, ErrorResponse errorResponse) {
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
