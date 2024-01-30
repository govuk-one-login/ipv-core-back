package uk.gov.di.ipv.core.library.exceptions;

import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@ExcludeFromGeneratedCoverageReport
public class SqsException extends Exception {
    public SqsException(Throwable e) {
        super(e);
    }

    public SqsException(String errorMessage) {
        super(errorMessage);
    }
}
