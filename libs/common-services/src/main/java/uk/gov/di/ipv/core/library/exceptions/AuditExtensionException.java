package uk.gov.di.ipv.core.library.exceptions;

import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@ExcludeFromGeneratedCoverageReport
public class AuditExtensionException extends Exception {
    public AuditExtensionException(Throwable e) {
        super(e);
    }

    public AuditExtensionException(String errorMessage) {
        super(errorMessage);
    }
}
