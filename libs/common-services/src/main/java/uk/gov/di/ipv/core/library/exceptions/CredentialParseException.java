package uk.gov.di.ipv.core.library.exceptions;

import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@ExcludeFromGeneratedCoverageReport
public class CredentialParseException extends Exception {
    public CredentialParseException(String message) {
        super(message);
    }

    public CredentialParseException(String message, Throwable cause) {
        super(message, cause);
    }
}
