package uk.gov.di.ipv.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

public class CredentialIssuerRequestDto {

    @JsonProperty("authorization_code")
    private String authorization_code;


    @JsonProperty("credential_issuer_id")
    private String credential_issuer_id;


    public CredentialIssuerRequestDto(
            @JsonProperty(value = "authorization_code") String authorization_code,
            @JsonProperty(value = "credential_issuer_id") String credential_issuer_id
    ) {
        this.authorization_code = authorization_code;
        this.credential_issuer_id = credential_issuer_id;
    }

    public String getAuthorization_code() {
        return authorization_code;
    }

    public String getCredential_issuer_id() {
        return credential_issuer_id;
    }
}
