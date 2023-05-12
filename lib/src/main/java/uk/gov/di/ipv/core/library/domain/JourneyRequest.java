package uk.gov.di.ipv.core.library.domain;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.Getter;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@Getter
@ExcludeFromGeneratedCoverageReport
public class JourneyRequest {
    @JsonProperty
    private String ipvSessionId;

    @JsonProperty
    private String ipAddress;

    @JsonCreator
    public JourneyRequest(
            @JsonProperty(value = "ipvSessionId") String ipvSessionId,
            @JsonProperty(value = "ipAddress") String ipAddress
    ) {
        this.ipvSessionId = ipvSessionId;
        this.ipAddress = ipAddress;
    }
}
