package uk.gov.di.ipv.core.library.criapiservice.exception;

import lombok.Getter;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;

@Getter
public class CriApiException extends Exception {
    private final ErrorResponse errorResponse;
    private final int httpStatusCode;

    public CriApiException(int httpStatusCode, ErrorResponse errorResponse) {
        super(errorResponse.getMessage());
        this.errorResponse = errorResponse;
        this.httpStatusCode = httpStatusCode;
    }
}
