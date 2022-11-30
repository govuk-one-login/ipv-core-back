package uk.gov.di.ipv.core.buildprovenuseridentitydetails.domain;

import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.domain.Address;

@ExcludeFromGeneratedCoverageReport
public class ProvenUserIdentityDetails {
    private String name;
    private Address addressDetails;
    private String dateOfBirth;

    public ProvenUserIdentityDetails() {}

    public ProvenUserIdentityDetails(String name, String dateOfBirth, Address addressDetails) {
        this.name = name;
        this.dateOfBirth = dateOfBirth;
        this.addressDetails = addressDetails;
    }

    public String getName() {
        return name;
    }

    public String getDateOfBirth() {
        return dateOfBirth;
    }

    public Address getAddressDetails() {
        return addressDetails;
    }

    public static class Builder {
        private String name;
        private String dateOfBirth;
        private Address addressDetails;

        public Builder setDateOfBirth(String dateOfBirth) {
            this.dateOfBirth = dateOfBirth;
            return this;
        }

        public Builder setAddressDetails(Address addressDetails) {
            this.addressDetails = addressDetails;
            return this;
        }

        public Builder setName(String name) {
            this.name = name;
            return this;
        }

        public ProvenUserIdentityDetails build() {
            return new ProvenUserIdentityDetails(name, dateOfBirth, addressDetails);
        }
    }
}
