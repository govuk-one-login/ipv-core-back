package uk.gov.di.ipv.core.processjourneystep.statemachine.exceptions;

import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@ExcludeFromGeneratedCoverageReport
public class UnknownStateException extends Exception {
    public UnknownStateException() {
        super();
    }

    public UnknownStateException(String message) {
        super(message);
    }

    public UnknownStateException(String message, Throwable cause) {
        super(message, cause);
    }

    public UnknownStateException(Throwable cause) {
        super(cause);
    }
}
