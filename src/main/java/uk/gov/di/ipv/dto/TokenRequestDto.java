package uk.gov.di.ipv.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.net.URI;

public class TokenRequestDto {
    @JsonProperty("code")
    private String code;

    @JsonProperty("redirect_uri")
    private URI redirect_uri;

    @JsonProperty("grant_type")
    private String grant_type;

    @JsonProperty("client_id")
    private String client_id;

    public TokenRequestDto(
            @JsonProperty(value="code") String code,
            @JsonProperty(value="redirect_uri") URI redirect_uri,
            @JsonProperty(value="grant_type") String grant_type,
            @JsonProperty(value="client_id") String client_id
    ) {
        this.code = code;
        this.redirect_uri = redirect_uri;
        this.grant_type = grant_type;
        this.client_id = client_id;
    }

    public String getCode() {
        return code;
    }

    public URI getRedirect_uri() {
        return redirect_uri;
    }

    public String getGrant_type() {
        return grant_type;
    }

    public String getClient_id() {
        return client_id;
    }
}
