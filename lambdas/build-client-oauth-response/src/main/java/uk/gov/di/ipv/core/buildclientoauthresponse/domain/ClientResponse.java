package uk.gov.di.ipv.core.buildclientoauthresponse.domain;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.domain.BaseResponse;

import java.util.Objects;

@ExcludeFromGeneratedCoverageReport
public class ClientResponse extends BaseResponse {
    @JsonProperty private final ClientDetails client;

    @JsonCreator
    public ClientResponse(@JsonProperty(value = "client", required = true) ClientDetails client) {
        this.client = client;
    }

    public ClientDetails getClient() {
        return client;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;
        if (!super.equals(o)) return false;
        ClientResponse that = (ClientResponse) o;
        return Objects.equals(client, that.client);
    }

    @Override
    public int hashCode() {
        return Objects.hash(super.hashCode(), client);
    }
}
