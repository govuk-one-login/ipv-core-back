package uk.gov.di.ipv.core.library.ais.exception;

import lombok.Getter;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;

@ExcludeFromGeneratedCoverageReport
public class AccountInterventionException extends Exception {

    @Getter private IpvSessionItem ipvSessionItem;

    public AccountInterventionException() {
        super(
                "Account intervention. This is thrown when an intervention has been discovered in ProcessCandidateIdentity.");
    }

    public AccountInterventionException(IpvSessionItem ipvSessionItem) {
        super(
                "Account intervention. This is thrown when an intervention has been discovered in ProcessCandidateIdentity.");
        this.ipvSessionItem = ipvSessionItem;
    }
}
