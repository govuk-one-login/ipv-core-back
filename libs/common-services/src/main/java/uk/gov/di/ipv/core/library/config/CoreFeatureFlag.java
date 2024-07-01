package uk.gov.di.ipv.core.library.config;

public enum CoreFeatureFlag implements FeatureFlag {
    UNUSED_PLACEHOLDER("unusedPlaceHolder"),
    RESET_IDENTITY("resetIdentity"),
    INHERITED_IDENTITY("inheritedIdentity"),
    REPROVE_IDENTITY_ENABLED("reproveIdentityEnabled"),
    REPEAT_FRAUD_CHECK("repeatFraudCheckEnabled"),
    TICF_CRI_BETA("ticfCriBeta"),
    EVCS_WRITE_ENABLED("evcsWriteEnabled"),
    EVCS_READ_ENABLED("evcsReadEnabled"),
    EVCS_TOKEN_READ_ENABLED("evcsTokenReadEnabled"),
    MFA_RESET("mfaResetEnabled"),
    P1_JOURNEYS_ENABLED("p1JourneysEnabled");

    private final String name;

    CoreFeatureFlag(String name) {
        this.name = name;
    }

    @Override
    public String getName() {
        return this.name;
    }
}
