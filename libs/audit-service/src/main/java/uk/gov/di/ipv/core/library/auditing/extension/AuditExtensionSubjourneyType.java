package uk.gov.di.ipv.core.library.auditing.extension;

import com.fasterxml.jackson.annotation.JsonProperty;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.domain.IpvJourneyTypes;

@ExcludeFromGeneratedCoverageReport
public record AuditExtensionSubjourneyType(
        @JsonProperty("journey_type") IpvJourneyTypes journeyType) implements AuditExtensions {}
