package uk.gov.di.ipv.core.library.auditing.extension;

import com.fasterxml.jackson.annotation.JsonProperty;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.enums.CandidateIdentityType;
import uk.gov.di.ipv.core.library.enums.Vot;

@ExcludeFromGeneratedCoverageReport
public record AuditExtensionCandidateIdentityType(
        @JsonProperty(value = "identity_type", required = true) CandidateIdentityType identityType,
        @JsonProperty(required = false) Vot vot)
        implements AuditExtensions {}
