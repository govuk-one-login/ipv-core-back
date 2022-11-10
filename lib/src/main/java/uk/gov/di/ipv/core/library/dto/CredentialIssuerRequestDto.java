package uk.gov.di.ipv.core.library.dto;

import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

import java.util.Optional;

@ExcludeFromGeneratedCoverageReport
public class CredentialIssuerRequestDto {
    private String authorizationCode;
    private String credentialIssuerId;
    private String ipvSessionId;
    private String redirectUri;
    private String state;
    private String error;
    private String errorDescription;
    private String ipAddress;

    public CredentialIssuerRequestDto() {}

    public CredentialIssuerRequestDto(
            String authorizationCode,
            String credentialIssuerId,
            String ipvSessionId,
            String redirectUri,
            String state,
            String error,
            String errorDescription,
            String ipAddress) {
        this.authorizationCode = authorizationCode;
        this.credentialIssuerId = credentialIssuerId;
        this.ipvSessionId = ipvSessionId;
        this.redirectUri = redirectUri;
        this.state = state;
        this.error = error;
        this.errorDescription = errorDescription;
        this.ipAddress = ipAddress;
    }

    public String getAuthorizationCode() {
        return authorizationCode;
    }

    public void setAuthorizationCode(String authorizationCode) {
        this.authorizationCode = authorizationCode;
    }

    public String getCredentialIssuerId() {
        return credentialIssuerId;
    }

    public void setCredentialIssuerId(String credentialIssuerId) {
        this.credentialIssuerId = credentialIssuerId;
    }

    public String getIpvSessionId() {
        return ipvSessionId;
    }

    public void setIpvSessionId(String ipvSessionId) {
        this.ipvSessionId = ipvSessionId;
    }

    public String getRedirectUri() {
        return redirectUri;
    }

    public void setRedirectUri(String redirectUri) {
        this.redirectUri = redirectUri;
    }

    public String getState() {
        return state;
    }

    public void setState(String state) {
        this.state = state;
    }

    public Optional<String> getError() {
        return Optional.ofNullable(error);
    }

    public void setError(String error) {
        this.error = error;
    }

    public Optional<String> getErrorDescription() {
        return Optional.ofNullable(errorDescription);
    }

    public void setErrorDescription(String errorDescription) {
        this.errorDescription = errorDescription;
    }

    public String getIpAddress() {
        return ipAddress;
    }

    public void setIpAddress(String ipAddress) {
        this.ipAddress = ipAddress;
    }
}
