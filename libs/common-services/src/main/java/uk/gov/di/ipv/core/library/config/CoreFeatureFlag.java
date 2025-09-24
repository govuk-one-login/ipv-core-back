package uk.gov.di.ipv.core.library.config;

public enum CoreFeatureFlag implements FeatureFlag {
    UNUSED_PLACEHOLDER("unusedPlaceHolder"),
    RESET_IDENTITY("resetIdentity"),
    REPEAT_FRAUD_CHECK("repeatFraudCheckEnabled"),
    MFA_RESET("mfaResetEnabled"),
    SQS_ASYNC("sqsAsync"),
    DL_AUTH_SOURCE_CHECK("drivingLicenceAuthCheck"),
    STORED_IDENTITY_SERVICE("storedIdentityServiceEnabled"),
    SIS_VERIFICATION("sisVerificationEnabled"),
    AIS_ENABLED("accountInterventionsEnabled");

    private final String name;

    CoreFeatureFlag(String name) {
        this.name = name;
    }

    @Override
    public String getName() {
        return this.name;
    }
}
