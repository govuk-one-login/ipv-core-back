package uk.gov.di.ipv.core.library.exceptions;

public class GetIpvSessionException extends RuntimeException {
    public GetIpvSessionException(String errorMessage, Exception e) {
        super(errorMessage, e);
    }

    public GetIpvSessionException(String errorMessage) {
        super(errorMessage);
    }
}
