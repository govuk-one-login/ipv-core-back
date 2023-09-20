package uk.gov.di.ipv.core.library.domain;

import lombok.Getter;
import lombok.Setter;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@Getter
@Setter
@ExcludeFromGeneratedCoverageReport
public class CheckDetail {
    private String checkMethod;
    private String identityCheckPolicy;
    private String activityFrom;
    private Integer biometricVerificationProcessLevel;
}
