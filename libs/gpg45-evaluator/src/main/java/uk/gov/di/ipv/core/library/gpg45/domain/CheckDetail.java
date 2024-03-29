package uk.gov.di.ipv.core.library.gpg45.domain;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import lombok.Getter;
import lombok.Setter;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@Getter
@Setter
@ExcludeFromGeneratedCoverageReport
@JsonIgnoreProperties(ignoreUnknown = true)
public class CheckDetail {
    private String checkMethod;
    private String identityCheckPolicy;
    private String activityFrom;
    private Integer biometricVerificationProcessLevel;
}
