package uk.gov.di.ipv.core.library.exceptions;

import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.domain.ErrorResponse;

import java.util.Map;

@ExcludeFromGeneratedCoverageReport
public class HttpResponseExceptionWithErrorBody extends Exception {
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

    public Map<String, Object> getErrorBody() {
        return Map.of(
                "error", errorResponse.getCode(), "error_description", errorResponse.getMessage());
    }

    public ErrorResponse getErrorResponse() {
        return errorResponse;
    }
}
