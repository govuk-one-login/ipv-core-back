package uk.gov.di.ipv.core.library.auditing.extension;

import com.fasterxml.jackson.annotation.JsonProperty;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.enums.CandidateIdentityType;
import uk.gov.di.ipv.core.library.enums.Vot;

@ExcludeFromGeneratedCoverageReport
public record AuditExtensionCandidateIdentityType(
        @JsonProperty(value = "identity_type", required = true) CandidateIdentityType identityType,
        @JsonProperty(value = "sis_record_created", required = true) Boolean sisRecordCreated,
        @JsonProperty(required = false) Vot vot,
        @JsonProperty(value = "max_vot", required = false) Vot maxVot)
        implements AuditExtensions {}
