package uk.gov.di.ipv.core.library.sis.exception;

import lombok.Getter;
import uk.gov.di.ipv.core.library.sis.enums.FailureCode;

@Getter
public class SisMatchException extends Exception {
    private FailureCode failureCode;

    public SisMatchException(FailureCode failureCode, String message) {
        super(message);
        this.failureCode = failureCode;
    }
}
