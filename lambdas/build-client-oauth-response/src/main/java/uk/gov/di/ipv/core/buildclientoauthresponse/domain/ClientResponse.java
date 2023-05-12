package uk.gov.di.ipv.core.buildclientoauthresponse.domain;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.domain.JourneyResponse;

@ExcludeFromGeneratedCoverageReport
public class ClientResponse extends JourneyResponse {
    @JsonProperty private final ClientDetails client;

    @JsonCreator
    public ClientResponse(
            @JsonProperty(value = "journey", required = true) String journey,
            @JsonProperty(value = "client", required = true) ClientDetails client) {
        super(journey);
        this.client = client;
    }

    public ClientDetails getClient() {
        return client;
    }
}
