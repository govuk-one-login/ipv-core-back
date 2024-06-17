package uk.gov.di.ipv.core.library.auditing.restricted;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.domain.BirthDate;
import uk.gov.di.ipv.core.library.domain.Name;

import java.util.List;

@ExcludeFromGeneratedCoverageReport
@JsonInclude(JsonInclude.Include.NON_NULL)
public class AuditRestrictedCheckCoi extends AuditRestrictedDeviceInformation {
    @JsonProperty private final List<Name> oldName;

    @JsonProperty private final List<Name> newName;

    @JsonProperty private final List<BirthDate> oldBirthDate;

    @JsonProperty private final List<BirthDate> newBirthDate;

    public AuditRestrictedCheckCoi(
            @JsonProperty List<Name> oldName,
            @JsonProperty List<Name> newName,
            @JsonProperty List<BirthDate> oldBirthDate,
            @JsonProperty List<BirthDate> newBirthDate,
            @JsonProperty(value = "device_information", required = true) String deviceInformation) {
        super(deviceInformation);
        this.oldName = oldName;
        this.newName = newName;
        this.oldBirthDate = oldBirthDate;
        this.newBirthDate = newBirthDate;
    }
}
;
