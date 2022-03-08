package uk.gov.di.ipv.core.library.domain;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
@ExcludeFromGeneratedCoverageReport
public class Address {
    private String type;
    private String organizationName;
    private String streetAddress;
    private String addressLocality;
    private String addressRegion;
    private String postalCode;
    private String addressCountry;

    public Address() {}

    public Address(
            String type,
            String organizationName,
            String streetAddress,
            String addressLocality,
            String addressRegion,
            String postalCode,
            String addressCountry) {
        this.type = type;
        this.organizationName = organizationName;
        this.streetAddress = streetAddress;
        this.addressLocality = addressLocality;
        this.addressRegion = addressRegion;
        this.postalCode = postalCode;
        this.addressCountry = addressCountry;
    }

    public String getType() {
        return type;
    }

    public void setType(String type) {
        this.type = type;
    }

    public String getOrganizationName() {
        return organizationName;
    }

    public void setOrganizationName(String organizationName) {
        this.organizationName = organizationName;
    }

    public String getStreetAddress() {
        return streetAddress;
    }

    public void setStreetAddress(String streetAddress) {
        this.streetAddress = streetAddress;
    }

    public String getAddressLocality() {
        return addressLocality;
    }

    public void setAddressLocality(String addressLocality) {
        this.addressLocality = addressLocality;
    }

    public String getAddressRegion() {
        return addressRegion;
    }

    public void setAddressRegion(String addressRegion) {
        this.addressRegion = addressRegion;
    }

    public String getPostalCode() {
        return postalCode;
    }

    public void setPostalCode(String postalCode) {
        this.postalCode = postalCode;
    }

    public String getAddressCountry() {
        return addressCountry;
    }

    public void setAddressCountry(String addressCountry) {
        this.addressCountry = addressCountry;
    }
}
