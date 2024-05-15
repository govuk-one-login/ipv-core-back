package uk.gov.di.ipv.core.library.auditing.restricted;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@ExcludeFromGeneratedCoverageReport
@Getter
public class DeviceInformation {
    @JsonInclude(JsonInclude.Include.NON_NULL)
    @JsonProperty("encoded")
    private final String encoded;

    public DeviceInformation(@JsonProperty(value = "encoded", required = true) String encoded) {
        this.encoded = encoded;
    }
}
