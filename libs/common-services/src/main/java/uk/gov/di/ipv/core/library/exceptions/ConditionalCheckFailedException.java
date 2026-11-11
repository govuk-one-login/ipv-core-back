package uk.gov.di.ipv.core.library.exceptions;

import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@ExcludeFromGeneratedCoverageReport
public class ConditionalCheckFailedException extends Exception {
    public ConditionalCheckFailedException() {
        super();
    }

    public ConditionalCheckFailedException(Exception e) {
        super(e);
    }
}
