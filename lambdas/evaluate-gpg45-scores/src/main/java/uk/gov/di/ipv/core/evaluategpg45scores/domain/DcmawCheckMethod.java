package uk.gov.di.ipv.core.evaluategpg45scores.domain;

import lombok.Getter;

@Getter
public class DcmawCheckMethod {
    private String checkMethod;
    private String identityCheckPolicy;
    private String activityFrom;
    private Integer biometricVerificationProcessLevel;
}
