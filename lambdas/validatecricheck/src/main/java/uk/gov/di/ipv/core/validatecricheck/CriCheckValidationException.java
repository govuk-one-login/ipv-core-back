package uk.gov.di.ipv.core.validatecricheck;

public class CriCheckValidationException extends Exception {
    private final int responseCode;

    public CriCheckValidationException(int responseCode) {
        this.responseCode = responseCode;
    }

    public int getResponseCode() {
        return responseCode;
    }
}
