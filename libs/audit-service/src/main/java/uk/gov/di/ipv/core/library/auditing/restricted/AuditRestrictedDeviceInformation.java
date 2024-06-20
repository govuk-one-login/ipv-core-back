package uk.gov.di.ipv.core.library.auditing.restricted;

import com.fasterxml.jackson.annotation.JsonProperty;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@ExcludeFromGeneratedCoverageReport
public record AuditRestrictedDeviceInformation(
        @JsonProperty("device_information") DeviceInformation deviceInformation)
        implements AuditRestrictedWithDeviceInformation {
    public AuditRestrictedDeviceInformation(String deviceInformation) {
        this(new DeviceInformation(deviceInformation));
    }
}
