package uk.gov.di.ipv.core.library.auditing.restricted;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@ExcludeFromGeneratedCoverageReport
@Getter
public class DeviceInformation {
    @JsonProperty("encoded")
    private String encoded = "";

    public DeviceInformation(@JsonProperty(value = "encoded", required = true) String encoded) {
        this.encoded = encoded;
    }
}
