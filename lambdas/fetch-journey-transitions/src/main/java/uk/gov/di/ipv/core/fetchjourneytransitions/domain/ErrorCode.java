package uk.gov.di.ipv.core.fetchjourneytransitions.domain;

public enum ErrorCode {
    UNEXPECTED_ERROR(0),
    CLOUD_WATCH_ERROR(1),
    CLOUD_WATCH_SLOW(2);


    private final int code;

    ErrorCode(int code) {
        this.code = code;
    }

    public int getCode() {
        return code;
    }
}
