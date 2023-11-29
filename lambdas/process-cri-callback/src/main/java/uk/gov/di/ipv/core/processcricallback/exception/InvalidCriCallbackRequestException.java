package uk.gov.di.ipv.core.processcricallback.exception;

import lombok.Getter;
import org.apache.http.HttpStatus;
import org.apache.http.client.HttpResponseException;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;

@Getter
public class InvalidCriCallbackRequestException extends HttpResponseException {
    private final ErrorResponse errorResponse;

    public InvalidCriCallbackRequestException(ErrorResponse errorResponse) {
        super(HttpStatus.SC_BAD_REQUEST, errorResponse.getMessage());
        this.errorResponse = errorResponse;
    }
}
