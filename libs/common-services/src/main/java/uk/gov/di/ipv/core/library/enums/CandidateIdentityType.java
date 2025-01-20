package uk.gov.di.ipv.core.library.enums;

import com.fasterxml.jackson.annotation.JsonProperty;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@ExcludeFromGeneratedCoverageReport
public enum CandidateIdentityType {
    @JsonProperty("existing")
    EXISTING,
    @JsonProperty("new")
    NEW,
    @JsonProperty("pending")
    PENDING,
    @JsonProperty("reverification")
    REVERIFICATION,
    @JsonProperty("incomplete")
    INCOMPLETE,
    @JsonProperty("update")
    UPDATE
}
