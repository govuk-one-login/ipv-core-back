package uk.gov.di.ipv.core.library.sis.audit;

import com.fasterxml.jackson.annotation.JsonProperty;
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

    @JsonProperty("max_vot")
    private final Vot maxVot;

    @JsonProperty("reconstructed_vot")
    private final Vot reconstructedVot;

    @JsonProperty("reconstructed_max_vot")
    private final Vot reconstructedMaxVot;

    @JsonProperty("is_valid")
    private final Boolean isValid;

    private final Boolean expired;

    @JsonProperty("verification_outcome")
    private final VerificationOutcome verificationOutcome;

    @JsonProperty("failure_code")
    private final FailureCode failureCode;

    public AuditExtensionsSisComparison(
            Vot vot,
            @JsonProperty("max_vot") Vot maxVot,
            @JsonProperty("reconstructed_vot") Vot reconstructedVot,
            @JsonProperty("reconstructed_max_vot") Vot reconstructedMaxVot,
            @JsonProperty("is_valid") Boolean isValid,
            Boolean expired,
            @JsonProperty("verification_outcome") VerificationOutcome verificationOutcome,
            @JsonProperty("failure_code") FailureCode failureCode) {
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
