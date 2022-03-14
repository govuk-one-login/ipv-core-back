package uk.gov.di.ipv.core.credentialissuer.domain;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

public class CriResponse {
    @JsonProperty private final String id;

    @JsonProperty private final String authorizeUrl;

    @JsonProperty private final String request;

    @JsonCreator
    public CriResponse(
            @JsonProperty(value = "id", required = true) String id,
            @JsonProperty(value = "authorizeUrl", required = true) String authorizeUrl,
            @JsonProperty(value = "request", required = true) String request) {
        this.id = id;
        this.authorizeUrl = authorizeUrl;
        this.request = request;
    }

    public String getId() {
        return id;
    }

    public String getAuthorizeUrl() {
        return authorizeUrl;
    }

    public String getRequest() {
        return request;
    }
}
