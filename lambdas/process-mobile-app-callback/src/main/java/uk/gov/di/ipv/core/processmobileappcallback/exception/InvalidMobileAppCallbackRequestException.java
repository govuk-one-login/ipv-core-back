package uk.gov.di.ipv.core.processmobileappcallback.exception;

import lombok.Getter;
import software.amazon.awssdk.http.HttpStatusCode;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;
import uk.gov.di.ipv.core.library.exceptions.HttpResponseExceptionWithErrorBody;

@Getter
public class InvalidMobileAppCallbackRequestException extends HttpResponseExceptionWithErrorBody {
    public InvalidMobileAppCallbackRequestException(ErrorResponse errorResponse) {
        super(HttpStatusCode.BAD_REQUEST, errorResponse);
    }
}
