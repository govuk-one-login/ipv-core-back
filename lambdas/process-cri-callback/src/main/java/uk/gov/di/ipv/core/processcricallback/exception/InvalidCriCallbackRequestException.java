package uk.gov.di.ipv.core.processcricallback.exception;

import lombok.Getter;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;

@Getter
public class InvalidCriCallbackRequestException extends Exception {
    private final ErrorResponse errorResponse;

    public InvalidCriCallbackRequestException(ErrorResponse errorResponse) {
        this.errorResponse = errorResponse;
    }
}
