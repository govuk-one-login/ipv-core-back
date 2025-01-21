package uk.gov.di.ipv.core.library.auditing.extension;

import com.fasterxml.jackson.annotation.JsonProperty;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@ExcludeFromGeneratedCoverageReport
public record AuditExtensionReverification(
        @JsonProperty("success") boolean success, @JsonProperty("failure_code") String failureCode)
        implements AuditExtensions {}
