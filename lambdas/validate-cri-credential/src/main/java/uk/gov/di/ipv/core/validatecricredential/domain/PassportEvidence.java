package uk.gov.di.ipv.core.validatecricredential.domain;

import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

import java.util.List;

@ExcludeFromGeneratedCoverageReport
public class PassportEvidence {

    private final int strengthScore;
    private final int validityScore;
    private final List<String> ci;

    public PassportEvidence(int strengthScore, int validityScore, List<String> ci) {
        this.strengthScore = strengthScore;
        this.validityScore = validityScore;
        this.ci = ci;
    }

    public int getStrengthScore() {
        return strengthScore;
    }

    public int getValidityScore() {
        return validityScore;
    }

    public List<String> getCi() {
        return ci;
    }
}
