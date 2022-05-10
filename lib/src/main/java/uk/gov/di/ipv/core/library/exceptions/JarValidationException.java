package uk.gov.di.ipv.core.library.exceptions;

import com.nimbusds.oauth2.sdk.ErrorObject;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@ExcludeFromGeneratedCoverageReport
public class JarValidationException extends Exception {
    private final ErrorObject errorObject;

    public JarValidationException(ErrorObject errorObject) {
        this.errorObject = errorObject;
    }

    public ErrorObject getErrorObject() {
        return errorObject;
    }
}
