package uk.gov.di.ipv.core.library.config;

public enum CoreFeatureFlag implements FeatureFlag {
    UNUSED_PLACEHOLDER("unusedPlaceHolder"),
    RESET_IDENTITY("resetIdentity"),
    INHERITED_IDENTITY("inheritedIdentity"),
    REPROVE_IDENTITY_ENABLED("reproveIdentityEnabled"),
    ALTERNATE_DOC_MITIGATION_ENABLED("alternateDocMitigationEnabled"),
    REPEAT_FRAUD_CHECK("repeatFraudCheckEnabled"),
    TICF_CRI_BETA("ticfCriBeta"),
    SESSION_CREDENTIALS_TABLE_WRITES("sessionCredentialsTableWrites");

    private final String name;

    CoreFeatureFlag(String name) {
        this.name = name;
    }

    @Override
    public String getName() {
        return this.name;
    }
}
