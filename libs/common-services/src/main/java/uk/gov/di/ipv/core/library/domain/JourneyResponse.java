package uk.gov.di.ipv.core.library.domain;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.EqualsAndHashCode;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@ExcludeFromGeneratedCoverageReport
@EqualsAndHashCode(callSuper = false)
public class JourneyResponse extends BaseResponse {
    @JsonProperty private final String journey;

    @JsonCreator
    public JourneyResponse(@JsonProperty(value = "journey", required = true) String journey) {
        this.journey = journey;
    }

    public String getJourney() {
        return journey;
    }

    public String toString() {
        return journey;
    }
}
