package uk.gov.di.ipv.core.library.auditing.restricted;

import com.fasterxml.jackson.annotation.JsonProperty;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.domain.BirthDate;
import uk.gov.di.ipv.core.library.domain.Name;
import uk.gov.di.ipv.core.library.domain.SocialSecurityRecord;

import java.util.List;

@ExcludeFromGeneratedCoverageReport
public record AuditRestrictedInheritedIdentity(
        List<Name> name,
        List<BirthDate> birthDate,
        List<SocialSecurityRecord> socialSecurityRecord,
        @JsonProperty(value = "device_information", required = true)
                DeviceInformation deviceInformation)
        implements AuditRestrictedWithDeviceInformation {}
