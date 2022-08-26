package uk.gov.di.ipv.core.evaluategpg45scores.domain;

import lombok.Getter;
import lombok.Setter;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@Getter
@Setter
@ExcludeFromGeneratedCoverageReport
public class DcmawScores {
    int strengthScore;
    int validityScore;
    int activityScore;
    int verificationScore;
}
