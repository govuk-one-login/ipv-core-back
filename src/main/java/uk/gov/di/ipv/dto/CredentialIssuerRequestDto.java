package uk.gov.di.ipv.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

public class CredentialIssuerRequestDto {

    private final String authorization_code;

    private final String credential_issuer_id;

    private final String redirect_uri;

    public CredentialIssuerRequestDto(
            @JsonProperty(value = "authorization_code", required = true) String authorization_code,
            @JsonProperty(value = "credential_issuer_id", required = true) String credential_issuer_id,
            @JsonProperty(value = "redirect_uri", required = true) String redirect_uri
    ) {
        this.authorization_code = authorization_code;
        this.credential_issuer_id = credential_issuer_id;
        this.redirect_uri = redirect_uri;
    }

    public String getAuthorization_code() {
        return authorization_code;
    }

    public String getCredential_issuer_id() {
        return credential_issuer_id;
    }

    public String getRedirect_uri() {
        return redirect_uri;
    }

}
