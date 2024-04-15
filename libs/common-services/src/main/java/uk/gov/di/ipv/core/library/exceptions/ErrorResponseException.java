package uk.gov.di.ipv.core.library.exceptions;

import uk.gov.di.ipv.core.library.domain.ErrorResponse;

public interface ErrorResponseException {
    ErrorResponse getErrorResponse();

    int getResponseCode();

    String getErrorReason();
}
