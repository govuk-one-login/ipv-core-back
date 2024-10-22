package uk.gov.di.ipv.core.library.service.exception;

import lombok.Getter;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;

@Getter
public class InvalidCriResponseException extends Exception {
    private final ErrorResponse errorResponse;

    public InvalidCriResponseException(ErrorResponse errorResponse) {
        super(errorResponse.getMessage());
        this.errorResponse = errorResponse;
    }
}
