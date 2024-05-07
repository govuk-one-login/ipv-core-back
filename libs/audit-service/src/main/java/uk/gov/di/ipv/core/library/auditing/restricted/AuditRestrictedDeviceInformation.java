package uk.gov.di.ipv.core.library.auditing.restricted;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Getter;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@ExcludeFromGeneratedCoverageReport
@Getter
public class AuditRestrictedDeviceInformation implements AuditRestricted {
    @JsonProperty("device_information")
    private final DeviceInformation deviceInformation;

    public AuditRestrictedDeviceInformation(
            @JsonProperty(value = "device_information", required = true) String deviceInformation) {
        this.deviceInformation = new DeviceInformation(deviceInformation);
    }
}
