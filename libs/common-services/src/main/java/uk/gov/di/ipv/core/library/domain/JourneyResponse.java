package uk.gov.di.ipv.core.library.domain;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.EqualsAndHashCode;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@ExcludeFromGeneratedCoverageReport
@EqualsAndHashCode(callSuper = false)
public class JourneyResponse extends BaseResponse {
    @JsonProperty(required = true)
    private final String journey;

    @JsonProperty(required = false)
    private final String clientOAuthSessionId;

    @JsonCreator
    public JourneyResponse(
            @JsonProperty(value = "journey", required = true) String journey,
            @JsonProperty(value = "clientOAuthSessionId") String clientOAuthSessionId) {
        this.journey = journey;
        this.clientOAuthSessionId = clientOAuthSessionId;
    }

    public JourneyResponse(String journey) {
        this(journey, null);
    }

    public String getJourney() {
        return journey;
    }

    public String toString() {
        return journey;
    }
}
