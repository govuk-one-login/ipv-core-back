package uk.gov.di.ipv.core.processcricallback.exception;

import lombok.Getter;
import org.apache.http.client.HttpResponseException;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;

@Getter
public class CriApiException extends HttpResponseException {
    private final ErrorResponse errorResponse;
    private final int httpStatusCode;

    public CriApiException(int httpStatusCode, ErrorResponse errorResponse) {
        super(httpStatusCode, errorResponse.getMessage());
        this.errorResponse = errorResponse;
        this.httpStatusCode = httpStatusCode;
    }
}
