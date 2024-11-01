package uk.gov.di.ipv.core.checkmobileappvcreceipt.exception;

import lombok.Getter;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;

@Getter
public class InvalidCheckMobileAppVcReceiptRequestException extends Exception {
    private final ErrorResponse errorResponse;

    public InvalidCheckMobileAppVcReceiptRequestException(ErrorResponse errorResponse) {
        super(errorResponse.getMessage());
        this.errorResponse = errorResponse;
    }
}
