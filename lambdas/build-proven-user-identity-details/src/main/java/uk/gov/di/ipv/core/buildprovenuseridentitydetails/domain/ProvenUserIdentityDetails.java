package uk.gov.di.ipv.core.buildprovenuseridentitydetails.domain;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;
import lombok.Data;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.domain.Address;
import uk.gov.di.ipv.core.library.domain.BaseResponse;

import java.util.List;

@ExcludeFromGeneratedCoverageReport
@Data
@Builder
public class ProvenUserIdentityDetails implements BaseResponse {
    @JsonProperty private final String name;
    @JsonProperty private final String dateOfBirth;
    @JsonProperty private final List<Address> addresses;

    @JsonCreator
    public ProvenUserIdentityDetails(
            @JsonProperty(value = "name") String name,
            @JsonProperty(value = "dateOfBirth") String dateOfBirth,
            @JsonProperty(value = "addresses") List<Address> addresses) {
        this.name = name;
        this.dateOfBirth = dateOfBirth;
        this.addresses = addresses;
    }
}
