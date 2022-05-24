package uk.gov.di.ipv.core.validatecricheck.domain;

import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@ExcludeFromGeneratedCoverageReport
public class KbvEvidence {

    private final int verificationScore;

    public KbvEvidence(int verificationScore) {
        this.verificationScore = verificationScore;
    }

    public int getVerificationScore() {
        return verificationScore;
    }
}
