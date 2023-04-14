package uk.gov.di.ipv.core.library.domain;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.EqualsAndHashCode;
import lombok.Getter;
import org.apache.http.HttpStatus;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@ExcludeFromGeneratedCoverageReport
@EqualsAndHashCode
@Getter
public class JourneyResponse {
    @JsonProperty private final String journey;

    @JsonProperty private final int statusCode;

    @JsonCreator
    public JourneyResponse(@JsonProperty(value = "journey", required = true) String journey) {
        this(journey, HttpStatus.SC_OK);
    }

    @JsonCreator
    public JourneyResponse(
            @JsonProperty(value = "journey", required = true) String journey,
            @JsonProperty(value = "statusCode", required = true) int statusCode) {
        this.journey = journey;
        this.statusCode = statusCode;
    }

    public String toString() {
        return journey;
    }
}
