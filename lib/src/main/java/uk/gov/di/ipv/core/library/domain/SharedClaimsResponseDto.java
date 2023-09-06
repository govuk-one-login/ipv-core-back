package uk.gov.di.ipv.core.library.domain;

import com.fasterxml.jackson.annotation.JsonPropertyOrder;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

import java.util.Set;

@ExcludeFromGeneratedCoverageReport
@JsonPropertyOrder({"name", "birthDate", "address", "socialSecurityRecord"})
public class SharedClaimsResponseDto {

    private final Set<Name> name;
    private final Set<BirthDate> birthDate;
    private final Set<Address> address;
    private final Set<SocialSecurityRecord> socialSecurityRecord;

    public SharedClaimsResponseDto(
            Set<Name> name,
            Set<BirthDate> birthDate,
            Set<Address> address,
            Set<SocialSecurityRecord> socialSecurityRecord) {
        this.name = name;
        this.birthDate = birthDate;
        this.address = address;
        this.socialSecurityRecord = socialSecurityRecord;
    }

    public Set<Name> getName() {
        return name;
    }

    public Set<BirthDate> getBirthDate() {
        return birthDate;
    }

    public Set<Address> getAddress() {
        return address;
    }

    public Set<SocialSecurityRecord> getSocialSecurityRecord() {
        return socialSecurityRecord;
    }
}
