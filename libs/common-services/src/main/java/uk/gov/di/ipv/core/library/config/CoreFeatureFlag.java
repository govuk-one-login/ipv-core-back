package uk.gov.di.ipv.core.library.config;

public enum CoreFeatureFlag implements FeatureFlag {
    UNUSED_PLACEHOLDER("unusedPlaceHolder"),
    DL_AUTH_SOURCE_CHECK("drivingLicenceAuthCheck"),
    SIS_VERIFICATION("sisVerificationEnabled"),
    INTERVENTION_REPROVE_VIA_APP_ONLY("reproveViaAppOnlyEnabled"),
    EVCS_API_UPDATES("evcsApiUpdatesEnabled"),
    MITIGATIONS_9020("mitigations9020Enabled"),
    OPEN_BANKING("openBankingEnabled");

    private final String name;

    CoreFeatureFlag(String name) {
        this.name = name;
    }

    @Override
    public String getName() {
        return this.name;
    }
}
