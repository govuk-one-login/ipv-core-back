package uk.gov.di.ipv.core.library.dto;

import com.fasterxml.jackson.annotation.JsonProperty;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@ExcludeFromGeneratedCoverageReport
public class CredentialIssuerErrorDto {
    private final String error;
    private final String errorDescription;
    private final String state;
    private final String credentialIssuerId;
    private final String ipvSessionId;
    private final String redirectUri;

    public CredentialIssuerErrorDto(
            @JsonProperty(value = "error") String error,
            @JsonProperty(value = "error_description", required = false) String errorDescription,
            @JsonProperty(value = "state", required = false) String state,
            @JsonProperty(value = "credential_issuer_id") String credentialIssuerId,
            @JsonProperty(value = "ipv_session_id") String ipvSessionId,
            @JsonProperty(value = "redirect_uri") String redirectUri) {
        this.error = error;
        this.errorDescription = errorDescription;
        this.state = state;
        this.credentialIssuerId = credentialIssuerId;
        this.ipvSessionId = ipvSessionId;
        this.redirectUri = redirectUri;
    }

    public String getError() {
        return error;
    }

    public String getErrorDescription() {
        return errorDescription;
    }

    public String getState() {
        return state;
    }

    public String getCredentialIssuerId() {
        return credentialIssuerId;
    }

    public String getIpvSessionId() {
        return ipvSessionId;
    }

    public String getRedirectUri() {
        return redirectUri;
    }
}
