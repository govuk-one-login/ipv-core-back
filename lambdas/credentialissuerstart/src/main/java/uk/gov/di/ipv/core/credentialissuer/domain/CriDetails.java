package uk.gov.di.ipv.core.credentialissuer.domain;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

public class CriDetails {
    @JsonProperty private final String id;

    @JsonProperty private final String ipvClientId;

    @JsonProperty private final String authorizeUrl;

    @JsonCreator
    public CriDetails(
            @JsonProperty(value = "id", required = true) String id,
            @JsonProperty(value = "ipvClientId", required = true) String ipvClientId,
            @JsonProperty(value = "authorizeUrl", required = true) String authorizeUrl) {
        this.id = id;
        this.ipvClientId = ipvClientId;
        this.authorizeUrl = authorizeUrl;
    }

    public String getId() {
        return id;
    }

    public String getIpvClientId() {
        return ipvClientId;
    }

    public String getAuthorizeUrl() {
        return authorizeUrl;
    }
}
