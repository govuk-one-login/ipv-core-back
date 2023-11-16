package uk.gov.di.ipv.core.processcricallback.exception;

import lombok.Getter;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;

@Getter
public class CriApiException extends RuntimeException {
    private final ErrorResponse errorResponse;
    private final int httpStatusCode;

    public CriApiException(int httpStatusCode, ErrorResponse errorResponse) {
        this.errorResponse = errorResponse;
        this.httpStatusCode = httpStatusCode;
    }
}
