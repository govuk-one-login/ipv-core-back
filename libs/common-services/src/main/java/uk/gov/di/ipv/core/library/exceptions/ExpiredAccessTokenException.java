package uk.gov.di.ipv.core.library.exceptions;

public class ExpiredAccessTokenException extends Exception {
    private final String expiredAt;

    public ExpiredAccessTokenException(String errorMessage, String expiredAt) {
        super(errorMessage);
        this.expiredAt = expiredAt;
    }

    public String getExpiredAt() {
        return expiredAt;
    }
}
