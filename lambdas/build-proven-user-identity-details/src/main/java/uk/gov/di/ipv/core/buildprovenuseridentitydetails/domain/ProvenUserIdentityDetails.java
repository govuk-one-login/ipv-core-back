package uk.gov.di.ipv.core.buildprovenuseridentitydetails.domain;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.domain.Address;

import java.util.List;

@ExcludeFromGeneratedCoverageReport
@NoArgsConstructor
@AllArgsConstructor
@Data
@Builder
public class ProvenUserIdentityDetails {
    private String name;
    private String dateOfBirth;
    private List<Address> addresses;
}
