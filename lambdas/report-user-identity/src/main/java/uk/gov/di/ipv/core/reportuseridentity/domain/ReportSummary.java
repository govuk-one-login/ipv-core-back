package uk.gov.di.ipv.core.reportuseridentity.domain;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@Builder
@ExcludeFromGeneratedCoverageReport
public record ReportSummary(
        @JsonProperty("Total P2") long totalP2Identities,
        @JsonProperty("Total P2 migrated") long totalP2IdentitiesMigrated,
        @JsonProperty("Total P1") long totalP1Identities,
        @JsonProperty("Total P0") long totalP0Identities) {}
