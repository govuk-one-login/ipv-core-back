package uk.gov.di.ipv.core.library.exceptions;

public class GetAccessTokenException extends Exception {
    public GetAccessTokenException(String errorMessage, Exception e) {
        super(errorMessage, e);
    }
}
