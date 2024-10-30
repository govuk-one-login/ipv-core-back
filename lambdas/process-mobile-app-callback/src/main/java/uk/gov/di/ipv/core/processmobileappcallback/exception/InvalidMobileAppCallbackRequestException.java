package uk.gov.di.ipv.core.processmobileappcallback.exception;

import lombok.Getter;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;

@Getter
public class InvalidMobileAppCallbackRequestException extends Exception {
    private final ErrorResponse errorResponse;

    public InvalidMobileAppCallbackRequestException(ErrorResponse errorResponse) {
        super(errorResponse.getMessage());
        this.errorResponse = errorResponse;
    }
}
