package uk.gov.di.ipv.core.library.domain;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;
import lombok.NoArgsConstructor;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@NoArgsConstructor
@Data
@ExcludeFromGeneratedCoverageReport
public class JourneyRequest {
    @JsonProperty private String ipvSessionId;

    @JsonProperty private String ipAddress;

    @JsonCreator
    public JourneyRequest(
            @JsonProperty(value = "ipvSessionId") String ipvSessionId,
            @JsonProperty(value = "ipAddress") String ipAddress) {
        this.ipvSessionId = ipvSessionId;
        this.ipAddress = ipAddress;
    }
}
