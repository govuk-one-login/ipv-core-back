package uk.gov.di.ipv.core.library.config;

public enum CoreFeatureFlag implements FeatureFlag {
    MITIGATION_ENABLED("mitigationEnabled"),
    BUNDLE_CIMIT_VC("bundleCimitVC");

    private final String name;

    CoreFeatureFlag(String name) {
        this.name = name;
    }

    @Override
    public String getName() {
        return this.name;
    }
}
