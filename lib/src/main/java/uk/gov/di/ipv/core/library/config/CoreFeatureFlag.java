package uk.gov.di.ipv.core.library.config;

public enum CoreFeatureFlag implements FeatureFlag {
    USE_CONTRA_INDICATOR_VC("useContraIndicatorVC"),
    USE_POST_MITIGATIONS("usePostMitigations"),
    MITIGATION_ENABLED("mitigationEnabled");

    private final String name;

    CoreFeatureFlag(String name) {
        this.name = name;
    }

    @Override
    public String getName() {
        return this.name;
    }
}
