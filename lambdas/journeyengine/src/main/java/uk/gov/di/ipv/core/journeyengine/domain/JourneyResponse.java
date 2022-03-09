package uk.gov.di.ipv.core.journeyengine.domain;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@ExcludeFromGeneratedCoverageReport
public class JourneyResponse {
    @JsonProperty private final String journey;

    @JsonCreator
    public JourneyResponse(@JsonProperty(value = "journey", required = true) String journey) {
        this.journey = journey;
    }

    public String getJourney() {
        return journey;
    }
}
