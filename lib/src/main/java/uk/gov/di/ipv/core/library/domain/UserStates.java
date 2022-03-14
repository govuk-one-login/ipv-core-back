package uk.gov.di.ipv.core.library.domain;

public enum UserStates {
    DEBUG_PAGE("page-ipv-debug"),
    INITIAL_IPV_JOURNEY("page-ipv-start"),
    TRANSITION_PAGE_1("page-cri-transition"),
    TRANSITION_PAGE_2("page-cri-transition"),
    CRI_UK_PASSPORT("cri-ukPassport"),
    CRI_ACTIVITY_HISTORY("cri-activityHistory"),
    CRI_ADDRESS("cri-Address"),
    CRI_FRAUD("cri-fraud"),
    CRI_KBV("cri-kbv");

    public final String value;

    UserStates(String value) {
        this.value = value;
    }
}
