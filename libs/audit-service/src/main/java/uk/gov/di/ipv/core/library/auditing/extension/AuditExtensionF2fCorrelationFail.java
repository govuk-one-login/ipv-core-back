package uk.gov.di.ipv.core.library.auditing.extension;

import com.fasterxml.jackson.annotation.JsonProperty;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@ExcludeFromGeneratedCoverageReport
public record AuditExtensionF2fCorrelationFail(
        @JsonProperty(value = "name_correlation_fail", required = true) boolean nameCorrelationFail,
        @JsonProperty(value = "dob_correlation_fail", required = true) boolean dobCorrelationFail)
        implements AuditExtensions {}
