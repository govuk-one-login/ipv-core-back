package uk.gov.di.ipv.core.library.exceptions;

public class HttpResponseException extends Throwable {
    private final int responseCode;

    public HttpResponseException(int responseCode, String errorMessage) {
        super(errorMessage);
        this.responseCode = responseCode;
    }

    public int getResponseCode() {
        return responseCode;
    }
}
