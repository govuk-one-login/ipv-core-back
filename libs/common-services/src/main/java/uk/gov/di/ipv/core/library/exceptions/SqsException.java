package uk.gov.di.ipv.core.library.exceptions;

import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@ExcludeFromGeneratedCoverageReport
public class SqsException extends Exception {
    public SqsException(Throwable cause) {
        super(cause);
    }

    public SqsException(String errorMessage) {
        super(errorMessage);
    }

    public SqsException(String errorMessage, Throwable cause) {
        super(errorMessage, cause);
    }
}
