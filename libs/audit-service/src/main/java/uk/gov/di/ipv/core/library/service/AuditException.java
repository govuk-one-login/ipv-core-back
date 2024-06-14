package uk.gov.di.ipv.core.library.service;

public class AuditException extends RuntimeException {
    public AuditException(String message, Exception e) {
        super(message, e);
    }
}
