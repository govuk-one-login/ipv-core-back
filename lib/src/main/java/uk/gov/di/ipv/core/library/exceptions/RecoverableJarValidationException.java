package uk.gov.di.ipv.core.library.exceptions;

import com.nimbusds.oauth2.sdk.ErrorObject;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@ExcludeFromGeneratedCoverageReport
public class RecoverableJarValidationException extends JarValidationException {
    private final String redirectUri;
    private final String clientId;
    private final String state;

    public RecoverableJarValidationException(
            ErrorObject errorObject, String redirectUri, String clientId, String state) {
        super(errorObject);
        this.redirectUri = redirectUri;
        this.clientId = clientId;
        this.state = state;
    }

    public String getRedirectUri() {
        return this.redirectUri;
    }

    public String getClientId() {
        return this.clientId;
    }

    public String getState() {
        return state;
    }
}
