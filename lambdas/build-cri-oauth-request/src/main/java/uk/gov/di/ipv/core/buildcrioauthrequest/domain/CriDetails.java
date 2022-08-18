package uk.gov.di.ipv.core.buildcrioauthrequest.domain;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;

@Getter
public class CriDetails {
    @JsonProperty private final String id;

    @JsonProperty private final String redirectUrl;

    @JsonCreator
    public CriDetails(
            @JsonProperty(value = "id", required = true) String id,
            @JsonProperty(value = "redirectUrl", required = true) String redirectUrl) {
        this.id = id;
        this.redirectUrl = redirectUrl;
    }
}
