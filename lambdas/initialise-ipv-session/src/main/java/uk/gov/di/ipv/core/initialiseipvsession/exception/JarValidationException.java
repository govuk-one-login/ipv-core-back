package uk.gov.di.ipv.core.initialiseipvsession.exception;

import com.nimbusds.oauth2.sdk.ErrorObject;
import lombok.AllArgsConstructor;
import lombok.Getter;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@AllArgsConstructor
@Getter
@ExcludeFromGeneratedCoverageReport
public class JarValidationException extends Exception {
    private final ErrorObject errorObject;

    public JarValidationException(ErrorObject errorObject, Throwable cause) {
        super(errorObject.getDescription(), cause);
        this.errorObject = errorObject;
    }
}
