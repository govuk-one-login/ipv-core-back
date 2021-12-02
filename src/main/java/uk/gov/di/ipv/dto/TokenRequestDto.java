package uk.gov.di.ipv.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.net.URI;

public class TokenRequestDto {
    @JsonProperty("code")
    private String code;

    @JsonProperty("redirect_uri")
    private URI redirectUri;

    @JsonProperty("grant_type")
    private String grantType;

    @JsonProperty("client_id")
    private String clientId;

    public TokenRequestDto(
            @JsonProperty(value = "code") String code,
            @JsonProperty(value = "redirect_uri") URI redirectUri,
            @JsonProperty(value = "grant_type") String grantType,
            @JsonProperty(value = "client_id") String clientId) {
        this.code = code;
        this.redirectUri = redirectUri;
        this.grantType = grantType;
        this.clientId = clientId;
    }

    public String getCode() {
        return code;
    }

    public URI getRedirectUri() {
        return redirectUri;
    }

    public String getGrantType() {
        return grantType;
    }

    public String getClientId() {
        return clientId;
    }
}
