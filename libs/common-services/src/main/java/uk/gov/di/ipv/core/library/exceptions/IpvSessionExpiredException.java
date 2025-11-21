package uk.gov.di.ipv.core.library.exceptions;

import uk.gov.di.ipv.core.library.domain.ErrorResponse;

public class IpvSessionExpiredException extends Exception {

    public IpvSessionExpiredException(ErrorResponse errorResponse) {
        super(errorResponse.getMessage());
    }
}
