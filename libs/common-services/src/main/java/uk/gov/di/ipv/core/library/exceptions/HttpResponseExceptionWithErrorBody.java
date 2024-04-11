package uk.gov.di.ipv.core.library.exceptions;

import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;

@ExcludeFromGeneratedCoverageReport
public class HttpResponseExceptionWithErrorBody extends Exception
        implements ErrorResponseException {
    private final int responseCode;
    private final ErrorResponse errorResponse;

    public HttpResponseExceptionWithErrorBody(int responseCode, ErrorResponse errorResponse) {
        this.responseCode = responseCode;
        this.errorResponse = errorResponse;
    }

    public int getResponseCode() {
        return responseCode;
    }

    public String getErrorReason() {
        return this.errorResponse.getMessage();
    }

    public ErrorResponse getErrorResponse() {
        return errorResponse;
    }
}
