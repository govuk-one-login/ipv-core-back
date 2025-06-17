package uk.gov.di.ipv.core.library.auditing.extension;

import com.fasterxml.jackson.annotation.JsonProperty;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@ExcludeFromGeneratedCoverageReport
public record AuditExtensionManualF2FReset(
        @JsonProperty(required = true, value = "user_id") String userId)
        implements AuditExtensions {}
