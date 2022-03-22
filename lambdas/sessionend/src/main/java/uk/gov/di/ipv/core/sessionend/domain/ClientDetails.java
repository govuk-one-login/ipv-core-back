package uk.gov.di.ipv.core.sessionend.domain;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

public class ClientDetails {
    @JsonProperty private String redirectUrl;
    @JsonProperty private String authCode;

    @JsonCreator
    public ClientDetails(
            @JsonProperty(value = "redirectUrl", required = true) String redirectUrl,
            @JsonProperty(value = "authCode", required = true) String authCode) {
        this.redirectUrl = redirectUrl;
        this.authCode = authCode;
    }

    public String getRedirectUrl() {
        return redirectUrl;
    }

    public String getAuthCode() {
        return authCode;
    }
}
