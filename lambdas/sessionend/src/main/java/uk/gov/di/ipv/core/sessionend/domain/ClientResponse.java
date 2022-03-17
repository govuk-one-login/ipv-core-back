package uk.gov.di.ipv.core.sessionend.domain;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@ExcludeFromGeneratedCoverageReport
public class ClientResponse {
    @JsonProperty private String redirectUrl;
    @JsonProperty private String authCode;

    @JsonCreator
    public ClientResponse(
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
