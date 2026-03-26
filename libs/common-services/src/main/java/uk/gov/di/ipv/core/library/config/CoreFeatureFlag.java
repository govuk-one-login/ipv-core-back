package uk.gov.di.ipv.core.library.config;

public enum CoreFeatureFlag implements FeatureFlag {
    UNUSED_PLACEHOLDER("unusedPlaceHolder"),
    REPEAT_FRAUD_CHECK("repeatFraudCheckEnabled"),
    SQS_ASYNC("sqsAsync"),
    DL_AUTH_SOURCE_CHECK("drivingLicenceAuthCheck"),
    SIS_VERIFICATION("sisVerificationEnabled"),
    AIS_STATE_CHECK("aisStateCheckEnabled"),
    INTERVENTION_REPROVE_VIA_APP_ONLY("reproveViaAppOnlyEnabled");

    private final String name;

    CoreFeatureFlag(String name) {
        this.name = name;
    }

    @Override
    public String getName() {
        return this.name;
    }
}
