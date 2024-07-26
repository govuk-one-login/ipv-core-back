package uk.gov.di.ipv.core.library.exceptions;

public class IpvSessionNotFoundException extends Exception {
    public IpvSessionNotFoundException(String errorMessage, Exception e) {
        super(errorMessage, e);
    }

    public IpvSessionNotFoundException(String errorMessage) {
        super(errorMessage);
    }
}
