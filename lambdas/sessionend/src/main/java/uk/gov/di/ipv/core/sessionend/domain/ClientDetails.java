package uk.gov.di.ipv.core.sessionend.domain;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonInclude.Include;
import com.fasterxml.jackson.annotation.JsonProperty;

@JsonInclude(Include.NON_EMPTY)
public class ClientDetails {
    @JsonProperty private String redirectUrl;
    @JsonProperty private String authCode;
    @JsonProperty private String state;

    @JsonCreator
    public ClientDetails(
            @JsonProperty(value = "redirectUrl", required = true) String redirectUrl,
            @JsonProperty(value = "authCode", required = true) String authCode,
            @JsonProperty(value = "state") String state) {
        this.redirectUrl = redirectUrl;
        this.authCode = authCode;
        this.state = state;
    }

    public String getRedirectUrl() {
        return redirectUrl;
    }

    public String getAuthCode() {
        return authCode;
    }

    public String getState() {
        return state;
    }
}
