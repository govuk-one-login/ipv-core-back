package uk.gov.di.ipv.core.library.exceptions;

import lombok.Getter;

@Getter
public class UnknownProcessIdentityType extends Exception {
    private final String processIdentityType;

    public UnknownProcessIdentityType(String checkType) {
        this.processIdentityType = checkType;
    }
}
