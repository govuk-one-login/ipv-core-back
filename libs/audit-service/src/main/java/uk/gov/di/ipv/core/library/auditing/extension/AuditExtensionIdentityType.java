package uk.gov.di.ipv.core.library.auditing.extension;

import com.fasterxml.jackson.annotation.JsonProperty;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.enums.IdentityType;
import uk.gov.di.ipv.core.library.enums.Vot;

@ExcludeFromGeneratedCoverageReport
public record AuditExtensionIdentityType(
        @JsonProperty(value = "identity_type", required = true) IdentityType identityType,
        @JsonProperty(required = false) Vot vot)
        implements AuditExtensions {}
