package uk.gov.di.ipv.core.credentialissuer.domain;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;

@Getter
public class CriDetails {
    @JsonProperty private final String id;

    @JsonProperty private final String ipvClientId;

    @JsonProperty private final String authorizeUrl;

    @JsonProperty private final String request;

    @JsonCreator
    public CriDetails(
            @JsonProperty(value = "id", required = true) String id,
            @JsonProperty(value = "ipvClientId", required = true) String ipvClientId,
            @JsonProperty(value = "authorizeUrl", required = true) String authorizeUrl,
            @JsonProperty(value = "request", required = true) String request) {
        this.id = id;
        this.ipvClientId = ipvClientId;
        this.authorizeUrl = authorizeUrl;
        this.request = request;
    }
}
