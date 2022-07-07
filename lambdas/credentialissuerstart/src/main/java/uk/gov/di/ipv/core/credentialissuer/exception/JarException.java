package uk.gov.di.ipv.core.credentialissuer.exception;

import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@ExcludeFromGeneratedCoverageReport
public class JarException extends Exception {
    private final int responseCode;

    public JarException(int responseCode) {
        this.responseCode = responseCode;
    }

    public int getResponseCode() {
        return responseCode;
    }
}
