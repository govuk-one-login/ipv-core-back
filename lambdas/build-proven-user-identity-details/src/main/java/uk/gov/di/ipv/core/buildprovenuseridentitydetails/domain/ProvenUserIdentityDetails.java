package uk.gov.di.ipv.core.buildprovenuseridentitydetails.domain;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;
import lombok.Data;
import lombok.EqualsAndHashCode;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.domain.Address;

import java.util.List;
import java.util.Map;

@EqualsAndHashCode(callSuper = false)
@ExcludeFromGeneratedCoverageReport
@Data
@Builder
public class ProvenUserIdentityDetails {
    @JsonProperty private final String name;
    @JsonProperty private final Map<String, String> formattedName;
    @JsonProperty private final String dateOfBirth;
    @JsonProperty private final List<Address> addresses;

    @JsonCreator
    public ProvenUserIdentityDetails(
            @JsonProperty(value = "name") String name,
            @JsonProperty(value = "formattedName") Map<String, String> formattedName,
            @JsonProperty(value = "dateOfBirth") String dateOfBirth,
            @JsonProperty(value = "addresses") List<Address> addresses) {
        this.name = name;
        this.formattedName = formattedName;
        this.dateOfBirth = dateOfBirth;
        this.addresses = addresses;
    }
}
