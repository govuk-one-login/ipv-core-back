package uk.gov.di.ipv.core.library.config;

public enum CoreFeatureFlag implements FeatureFlag {
    UNUSED_PLACEHOLDER("unusedPlaceHolder"),
    DL_AUTH_SOURCE_CHECK("drivingLicenceAuthCheck"),
    SIS_VERIFICATION("sisVerificationEnabled"),
    MITIGATIONS_9020("mitigations9020Enabled"),
    F2F_RETRY("f2fRetryEnabled");

    private final String name;

    CoreFeatureFlag(String name) {
        this.name = name;
    }

    @Override
    public String getName() {
        return this.name;
    }
}
