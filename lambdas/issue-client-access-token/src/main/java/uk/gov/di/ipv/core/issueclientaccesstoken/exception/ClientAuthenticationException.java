package uk.gov.di.ipv.core.issueclientaccesstoken.exception;

import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@ExcludeFromGeneratedCoverageReport
public class ClientAuthenticationException extends Exception {
    public ClientAuthenticationException(String message) {
        super(message);
    }

    public ClientAuthenticationException(Throwable e) {
        super(e);
    }
}
