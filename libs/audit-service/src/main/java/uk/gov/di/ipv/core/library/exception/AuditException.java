package uk.gov.di.ipv.core.library.exception;

public class AuditException extends RuntimeException {
    public AuditException(String message, Exception e) {
        super(message, e);
    }
}
