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
    private final Vot vot;
    private final Vot maxVot;
    private final Vot reconstructedVot;
    private final Vot reconstructedMaxVot;
    private final Boolean isValid;
    private final Boolean expired;
    private final VerificationOutcome verificationOutcome;
    private final FailureCode failureCode;

    public AuditExtensionsSisComparison(
            Vot vot,
            Vot maxVot,
            Vot reconstructedVot,
            Vot reconstructedMaxVot,
            Boolean isValid,
            Boolean expired,
            VerificationOutcome verificationOutcome,
            FailureCode failureCode) {
        this.vot = vot;
        this.maxVot = maxVot;
        this.reconstructedVot = reconstructedVot;
        this.reconstructedMaxVot = reconstructedMaxVot;
        this.isValid = isValid;
        this.expired = expired;
        this.verificationOutcome = verificationOutcome;
        this.failureCode = failureCode;
    }
}
