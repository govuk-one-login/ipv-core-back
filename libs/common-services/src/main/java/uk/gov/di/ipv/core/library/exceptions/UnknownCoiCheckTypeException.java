package uk.gov.di.ipv.core.library.exceptions;

import lombok.Getter;

@Getter
public class UnknownCoiCheckTypeException extends Exception {
    private final String checkType;

    public UnknownCoiCheckTypeException(String checkType) {
        this.checkType = checkType;
    }
}
