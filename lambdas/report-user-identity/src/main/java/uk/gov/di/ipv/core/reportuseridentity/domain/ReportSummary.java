package uk.gov.di.ipv.core.reportuseridentity.domain;

import com.fasterxml.jackson.annotation.JsonProperty;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@ExcludeFromGeneratedCoverageReport
public class ReportSummary {
    @JsonProperty("Total P2")
    private int totalP2Identities;

    @JsonProperty("Total P1")
    private int totalP1Identities;

    @JsonProperty("Total P0")
    private int totalP0Identities;
}
