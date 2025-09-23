package uk.gov.di.ipv.core.library.exceptions;

public class ConfigParseException extends RuntimeException {
    public ConfigParseException(String message) {
        super(message);
    }

    public ConfigParseException(String message, Exception e) {
        super(message, e);
    }
}
