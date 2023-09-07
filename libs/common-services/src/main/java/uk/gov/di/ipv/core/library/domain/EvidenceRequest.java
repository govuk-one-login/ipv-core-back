package uk.gov.di.ipv.core.library.domain;

import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@ExcludeFromGeneratedCoverageReport
@JsonPropertyOrder({"strengthScore"})
public class EvidenceRequest {
    private final int strengthScore;

    public EvidenceRequest(int strengthScore) {

        this.strengthScore = strengthScore;
    }

    public int getStrengthScore() {
        return strengthScore;
    }
}
