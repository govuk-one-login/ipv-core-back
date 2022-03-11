package uk.gov.di.ipv.core.library.domain;

public enum UserStates {
    DEBUG_PAGE("core:debugPage"),
    INITIAL_IPV_JOURNEY("core:initalJourney"),
    TRANSITION_PAGE_1("core:transitionPage1"),
    TRANSITION_PAGE_2("core:transitionPage2"),
    CRI_UK_PASSPORT("cri:ukPassport"),
    CRI_ACTIVITY_HISTORY("cri:activityHistory"),
    CRI_ADDRESS("cri:Address"),
    CRI_FRAUD("cri:fraud"),
    CRI_KBV("cri:kbv");

    public final String value;

    private UserStates(String value) {
        this.value = value;
    }

    public static UserStates fromValue(String value) {
        for (UserStates state : values()) {
            if (state.value.equals(value)) {
                return state;
            }
        }
        return null;
    }
}
