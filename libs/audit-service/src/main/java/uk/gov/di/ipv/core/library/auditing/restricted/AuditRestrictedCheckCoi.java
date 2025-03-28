package uk.gov.di.ipv.core.library.auditing.restricted;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.model.BirthDate;
import uk.gov.di.model.Name;
import uk.gov.di.model.PostalAddress;

import java.util.List;

@ExcludeFromGeneratedCoverageReport
public record AuditRestrictedCheckCoi(
        @JsonInclude(JsonInclude.Include.NON_NULL) List<Name> oldName,
        @JsonInclude(JsonInclude.Include.NON_NULL) List<Name> newName,
        @JsonInclude(JsonInclude.Include.NON_NULL) List<BirthDate> oldBirthDate,
        @JsonInclude(JsonInclude.Include.NON_NULL) List<BirthDate> newBirthDate,
        @JsonInclude(JsonInclude.Include.NON_NULL) List<PostalAddress> oldAddress,
        @JsonInclude(JsonInclude.Include.NON_NULL) List<PostalAddress> newAddress,
        @JsonProperty(value = "device_information", required = true)
                DeviceInformation deviceInformation)
        implements AuditRestrictedWithDeviceInformation {}
