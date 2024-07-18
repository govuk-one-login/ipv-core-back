package uk.gov.di.ipv.core.library.exceptions;

public class ConfigParameterNotFoundException extends RuntimeException {
    public ConfigParameterNotFoundException(String parameter) {
        super(String.format("Parameter not found in config: %s", parameter));
    }
}
