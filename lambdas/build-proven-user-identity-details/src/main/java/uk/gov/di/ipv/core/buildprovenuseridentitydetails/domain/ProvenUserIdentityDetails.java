package uk.gov.di.ipv.core.buildprovenuseridentitydetails.domain;

import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.domain.Address;

import java.util.List;

@ExcludeFromGeneratedCoverageReport
public class ProvenUserIdentityDetails {
    private String name;
    private String dateOfBirth;
    private List<Address> addresses;

    public ProvenUserIdentityDetails() {}

    public ProvenUserIdentityDetails(String name, String dateOfBirth, List<Address> addresses) {
        this.name = name;
        this.dateOfBirth = dateOfBirth;
        this.addresses = addresses;
    }

    public String getName() {
        return name;
    }

    public String getDateOfBirth() {
        return dateOfBirth;
    }

    public List<Address> getAddresses() {
        return addresses;
    }

    public static class Builder {
        private String name;
        private String dateOfBirth;
        private List<Address> addresses;

        public Builder setDateOfBirth(String dateOfBirth) {
            this.dateOfBirth = dateOfBirth;
            return this;
        }

        public Builder setAddresses(List<Address> addresses) {
            this.addresses = addresses;
            return this;
        }

        public Builder setName(String name) {
            this.name = name;
            return this;
        }

        public ProvenUserIdentityDetails build() {
            return new ProvenUserIdentityDetails(name, dateOfBirth, addresses);
        }
    }
}
