package uk.gov.di.ipv.core.library.config;

public enum CoreFeatureFlag implements FeatureFlag {
    UNUSED_PLACEHOLDER("unusedPlaceHolder"),
    RESET_IDENTITY("resetIdentity"),
    INHERITED_IDENTITY("inheritedIdentity"),
    REPEAT_FRAUD_CHECK("repeatFraudCheckEnabled"),
    MFA_RESET("mfaResetEnabled"),
    P1_JOURNEYS_ENABLED("p1JourneysEnabled"),
    SQS_ASYNC("sqsAsync"),
    KID_JAR_HEADER("kidJarHeaderEnabled"),
    DL_AUTH_SOURCE_CHECK("drivingLicenceAuthCheck"),
    STORED_IDENTITY_SERVICE("storedIdentityServiceEnabled");

    private final String name;

    CoreFeatureFlag(String name) {
        this.name = name;
    }

    @Override
    public String getName() {
        return this.name;
    }
}
