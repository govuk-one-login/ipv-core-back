package uk.gov.di.ipv.core.library.exceptions;

import lombok.Getter;

@Getter
public class UnknownResetTypeException extends Exception {
    private final String resetType;

    public UnknownResetTypeException(String resetType) {
        this.resetType = resetType;
    }
}
