package uk.gov.di.ipv.core.library.auditing.restricted;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.domain.BirthDate;
import uk.gov.di.ipv.core.library.domain.Name;

import java.util.List;

@ExcludeFromGeneratedCoverageReport
public record AuditRestrictedCheckCoi(
        @JsonInclude(JsonInclude.Include.NON_NULL) List<Name> oldName,
        @JsonInclude(JsonInclude.Include.NON_NULL) List<Name> newName,
        @JsonInclude(JsonInclude.Include.NON_NULL) List<BirthDate> oldBirthDate,
        @JsonInclude(JsonInclude.Include.NON_NULL) List<BirthDate> newBirthDate,
        @JsonProperty(value = "device_information", required = true)
                DeviceInformation deviceInformation)
        implements AuditRestricted {}
