package uk.gov.di.ipv.core.validatecricheck.domain;

import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

import java.util.List;

@ExcludeFromGeneratedCoverageReport
public class FraudEvidence {
    private final int identityFraudScore;
    private final List<String> ci;

    public FraudEvidence(int identityFraudScore, List<String> ci) {
        this.identityFraudScore = identityFraudScore;
        this.ci = ci;
    }

    public int getIdentityFraudScore() {
        return identityFraudScore;
    }

    public List<String> getCi() {
        return ci;
    }
}
