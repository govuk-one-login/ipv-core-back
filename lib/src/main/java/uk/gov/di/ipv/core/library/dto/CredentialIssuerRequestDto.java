package uk.gov.di.ipv.core.library.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

public class CredentialIssuerRequestDto {

    private final String authorizationCode;

    private final String credentialIssuerId;

    private final String ipvSessionId;

    private final String redirectUri;

    public CredentialIssuerRequestDto(
            @JsonProperty(value = "authorization_code") String authorizationCode,
            @JsonProperty(value = "credential_issuer_id") String credentialIssuerId,
            @JsonProperty(value = "ipv_session_id") String ipvSessionId,
            @JsonProperty(value = "redirect_uri") String redirectUri) {
        this.authorizationCode = authorizationCode;
        this.credentialIssuerId = credentialIssuerId;
        this.ipvSessionId = ipvSessionId;
        this.redirectUri = redirectUri;
    }

    public String getAuthorizationCode() {
        return authorizationCode;
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
