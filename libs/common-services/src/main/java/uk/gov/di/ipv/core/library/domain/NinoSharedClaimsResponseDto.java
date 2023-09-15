package uk.gov.di.ipv.core.library.domain;

import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

import java.util.Set;

@ExcludeFromGeneratedCoverageReport
@JsonPropertyOrder({"name", "birthDate", "address", "socialSecurityRecord"})
public class NinoSharedClaimsResponseDto extends SharedClaimsResponseDto {
    private final Set<SocialSecurityRecord> socialSecurityRecord;

    public NinoSharedClaimsResponseDto(
            Set<Name> name,
            Set<BirthDate> birthDate,
            Set<Address> address,
            Set<SocialSecurityRecord> socialSecurityRecord) {
        super(name, birthDate, address);
        this.socialSecurityRecord = socialSecurityRecord;
    }

    public Set<SocialSecurityRecord> getSocialSecurityRecord() {
        return socialSecurityRecord;
    }
}
