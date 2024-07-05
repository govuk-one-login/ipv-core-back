package uk.gov.di.ipv.core.library.exceptions;

import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@ExcludeFromGeneratedCoverageReport
public class ItemAlreadyExistsException extends Exception {
    public ItemAlreadyExistsException() {
        super();
    }

    public ItemAlreadyExistsException(Exception e) {
        super(e);
    }
}
