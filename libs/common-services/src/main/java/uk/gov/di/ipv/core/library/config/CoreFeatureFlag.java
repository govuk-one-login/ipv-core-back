package uk.gov.di.ipv.core.library.config;

public enum CoreFeatureFlag implements FeatureFlag {
    UNUSED_PLACEHOLDER("unusedPlaceHolder"),
    RESET_IDENTITY("resetIdentity"),
    INHERITED_IDENTITY("inheritedIdentity"),
    REPEAT_FRAUD_CHECK("repeatFraudCheckEnabled"),
    TICF_CRI_BETA("ticfCriBeta"),
    EVCS_WRITE_ENABLED("evcsWriteEnabled"),
    EVCS_ASYNC_WRITE_ENABLED("evcsAsyncWriteEnabled"),
    EVCS_READ_ENABLED("evcsReadEnabled"),
    MFA_RESET("mfaResetEnabled"),
    P1_JOURNEYS_ENABLED("p1JourneysEnabled"),
    SQS_ASYNC("sqsAsync");

    private final String name;

    CoreFeatureFlag(String name) {
        this.name = name;
    }

    @Override
    public String getName() {
        return this.name;
    }
}
