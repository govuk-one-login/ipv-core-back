package uk.gov.di.ipv.core.checkmobileappvcreceipt.exception;

import lombok.Getter;
import software.amazon.awssdk.http.HttpStatusCode;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;

@Getter
public class InvalidCheckMobileAppVcReceiptRequestException
        extends HttpResponseExceptionWithErrorBody {
    public InvalidCheckMobileAppVcReceiptRequestException(ErrorResponse errorResponse) {
        super(HttpStatusCode.BAD_REQUEST, errorResponse);
    }
}
