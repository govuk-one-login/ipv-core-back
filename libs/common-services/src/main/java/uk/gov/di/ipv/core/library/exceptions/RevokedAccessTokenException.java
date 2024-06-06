package uk.gov.di.ipv.core.library.exceptions;

public class RevokedAccessTokenException extends Exception {
    private final String revokedAt;

    public RevokedAccessTokenException(String errorMessage, String revokedAt) {
        super(errorMessage);
        this.revokedAt = revokedAt;
    }

    public String getRevokedAt() {
        return revokedAt;
    }
}
