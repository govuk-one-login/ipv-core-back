package uk.gov.di.ipv.core.buildprovenuseridentitydetails.domain;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;
import lombok.Data;
import lombok.EqualsAndHashCode;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.domain.Address;
import uk.gov.di.model.NamePart;

import java.util.List;

@EqualsAndHashCode(callSuper = false)
@ExcludeFromGeneratedCoverageReport
@Data
@Builder
public class ProvenUserIdentityDetails {
    @JsonProperty private final String name;
    @JsonProperty private final List<NamePart> nameParts;
    @JsonProperty private final String dateOfBirth;
    @JsonProperty private final List<Address> addresses;

    @JsonCreator
    public ProvenUserIdentityDetails(
            @JsonProperty(value = "name") String name,
            @JsonProperty(value = "nameParts") List<NamePart> nameParts,
            @JsonProperty(value = "dateOfBirth") String dateOfBirth,
            @JsonProperty(value = "addresses") List<Address> addresses) {
        this.name = name;
        this.nameParts = nameParts;
        this.dateOfBirth = dateOfBirth;
        this.addresses = addresses;
    }
}
