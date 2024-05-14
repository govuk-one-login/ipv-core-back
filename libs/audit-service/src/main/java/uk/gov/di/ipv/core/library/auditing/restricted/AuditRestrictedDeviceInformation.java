package uk.gov.di.ipv.core.library.auditing.restricted;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@ExcludeFromGeneratedCoverageReport
@Getter
public class AuditRestrictedDeviceInformation implements AuditRestricted {
    @JsonInclude(JsonInclude.Include.NON_NULL)
    @JsonProperty("device_information")
    private final DeviceInformation deviceInformation;

    public AuditRestrictedDeviceInformation(
            @JsonProperty(value = "device_information", required = false)
                    String deviceInformation) {
        this.deviceInformation =
                deviceInformation != null ? new DeviceInformation(deviceInformation) : null;
    }
}
