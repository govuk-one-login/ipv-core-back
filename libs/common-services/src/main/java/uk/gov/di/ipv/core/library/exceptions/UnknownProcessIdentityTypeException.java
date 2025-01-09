package uk.gov.di.ipv.core.library.exceptions;

import lombok.Getter;

@Getter
public class UnknownProcessIdentityTypeException extends Exception {
    private final String processIdentityType;

    public UnknownProcessIdentityTypeException(String checkType) {
        this.processIdentityType = checkType;
    }
}
