package uk.gov.di.ipv.core.library.enums;

import java.util.Arrays;

public enum TicfCode {
    NO_INTERVENTION("00"),
    ACCOUNT_SUSPENDED("01"),
    ACCOUNT_UNSUSPENDED("02"),
    ACCOUNT_BLOCKED("03"),
    FORCED_USER_PASSWORD_RESET("04"),
    FORCED_USER_IDENTITY_VERIFY("05"),
    FORCED_USER_PASSWORD_RESET_AND_IDENTITY_VERIFY("06"),
    ACCOUNT_UNBLOCKED("07");

    private final String code;

    TicfCode(String code) {
        this.code = code;
    }

    public static TicfCode fromCode(String code) {
        return Arrays.stream(values())
                .filter(ticfCode -> ticfCode.code.equals(code))
                .findFirst()
                .orElse(null);
    }
}
