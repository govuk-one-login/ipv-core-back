package uk.gov.di.ipv.core.library.config;

import lombok.Getter;

@Getter
public enum FeatureFlag {
    USE_CONTRA_INDICATOR_VC("useContraIndicatorVC"),
    USE_POST_MITIGATIONS("usePostMitigations"),
    MITIGATION_ENABLED("mitigationEnabled");

    private final String name;

    FeatureFlag(String name) {
        this.name = name;
    }
}
