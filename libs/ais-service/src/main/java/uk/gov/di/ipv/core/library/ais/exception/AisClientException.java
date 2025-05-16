package uk.gov.di.ipv.core.library.ais.exception;

public class AisClientException extends Exception {
    public AisClientException(String message, Exception e) {
        super(message, e);
    }
}
