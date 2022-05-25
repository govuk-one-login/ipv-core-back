package uk.gov.di.ipv.core.library.domain;

import com.nimbusds.oauth2.sdk.ErrorObject;

public class CredentialIssuerException extends RuntimeException {

    private final ErrorObject errorObject;

    private final int httpStatusCode;

    public CredentialIssuerException(int httpStatusCode, ErrorObject errorObject) {
        this.errorObject = errorObject;
        this.httpStatusCode = httpStatusCode;
    }

    public ErrorObject getErrorObject() {
        return errorObject;
    }

    public int getHttpStatusCode() {
        return httpStatusCode;
    }
}
