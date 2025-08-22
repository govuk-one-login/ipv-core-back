package uk.gov.di.ipv.core.library.ais.exception;

import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@ExcludeFromGeneratedCoverageReport
public class AccountInterventionException extends Exception {

    public AccountInterventionException() {
        super("Not allowed account intervention has been detected.");
    }
}
