package uk.gov.di.ipv.core.library.sis.audit;

import lombok.Getter;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.auditing.extension.AuditExtensions;
import uk.gov.di.ipv.core.library.enums.Vot;
import uk.gov.di.ipv.core.library.sis.enums.FailureCode;
import uk.gov.di.ipv.core.library.sis.enums.VerificationOutcome;

@ExcludeFromGeneratedCoverageReport
@Getter
public class AuditExtensionsSisComparison implements AuditExtensions {
    private final Vot sisVot;
    private final Boolean isValid;
    private final Boolean expired;
    private final VerificationOutcome outcome;
    private final FailureCode failureCode;

    public AuditExtensionsSisComparison(
            Vot sisVot,
            Boolean isValid,
            Boolean expired,
            VerificationOutcome outcome,
            FailureCode failureCode) {
        this.sisVot = sisVot;
        this.isValid = isValid;
        this.expired = expired;
        this.outcome = outcome;
        this.failureCode = failureCode;
    }
}
