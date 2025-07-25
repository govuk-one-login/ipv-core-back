package uk.gov.di.ipv.core.library.ais.exception;

import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@ExcludeFromGeneratedCoverageReport
public class AccountInterventionException extends Exception {
    public AccountInterventionException() {
        super(
                "Account intervention. This is thrown when an intervention has been discovered in ProcessCandidateIdentity.");
    }
}
