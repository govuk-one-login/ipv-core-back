package uk.gov.di.ipv.core.library.domain;

public enum UserStates {
    DEBUG_PAGE("page-ipv-debug"),
    INITIAL_IPV_JOURNEY("initial-ipv-journey"),
    IPV_IDENTITY_START_PAGE("page-ipv-identity-start"),
    PRE_KBV_TRANSITION_PAGE("page-pre-kbv-transition"),
    IPV_SUCCESS_PAGE("page-ipv-success"),
    CRI_UK_PASSPORT("cri-ukPassport"),
    CRI_ACTIVITY_HISTORY("cri-activityHistory"),
    CRI_ADDRESS("cri-Address"),
    CRI_FRAUD("cri-fraud"),
    CRI_KBV("cri-kbv"),
    CRI_ERROR("cri-error"),
    IPV_ERROR_PAGE("page-ipv-error"),
    PYI_TECHNICAL_ERROR_PAGE("pyi-technical"),
    PYI_TECHNICAL_UNRECOVERABLE_ERROR_PAGE("pyi-technical-unrecoverable");

    public final String value;

    UserStates(String value) {
        this.value = value;
    }
}
