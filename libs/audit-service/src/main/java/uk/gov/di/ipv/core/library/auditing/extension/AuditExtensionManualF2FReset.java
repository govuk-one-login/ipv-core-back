package uk.gov.di.ipv.core.library.auditing.extension;

import com.fasterxml.jackson.annotation.JsonProperty;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@ExcludeFromGeneratedCoverageReport
public record AuditExtensionManualF2FReset(@JsonProperty(value = "user", required = true) User user)
        implements AuditExtensions {
    public record User(@JsonProperty(value = "user_id", required = true) String userId) {}
}
