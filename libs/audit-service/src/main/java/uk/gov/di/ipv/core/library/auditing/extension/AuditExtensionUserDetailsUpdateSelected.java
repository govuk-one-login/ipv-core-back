package uk.gov.di.ipv.core.library.auditing.extension;

import com.fasterxml.jackson.annotation.JsonProperty;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

import java.util.List;

@ExcludeFromGeneratedCoverageReport
public record AuditExtensionUserDetailsUpdateSelected(
        @JsonProperty("update_fields") List<String> updateFields,
        @JsonProperty("update_supported") boolean updateSupported)
        implements AuditExtensions {}
