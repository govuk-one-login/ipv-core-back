package uk.gov.di.ipv.core.library.helpers.vocab;

import uk.gov.di.model.PostalAddress;

public class PostalAddressGenerator {
    private PostalAddressGenerator() {}

    public static PostalAddress createPostalAddress(
            String buildingNumber,
            String buildingName,
            String streetName,
            String postalCode,
            String addressLocality,
            String addressCountry,
            Long uprn,
            String validFrom,
            String validUntil) {
        var postalAddress = new PostalAddress();
        postalAddress.setBuildingNumber(buildingNumber);
        postalAddress.setBuildingName(buildingName);
        postalAddress.setStreetName(streetName);
        postalAddress.setPostalCode(postalCode);
        postalAddress.setAddressLocality(addressLocality);
        postalAddress.setAddressCountry(addressCountry);
        postalAddress.setUprn(uprn);
        postalAddress.setValidFrom(validFrom);
        postalAddress.setValidUntil(validUntil);

        return postalAddress;
    }

    public static PostalAddress createPostalAddress(
            String buildingNumber,
            String buildingName,
            String streetName,
            String postalCode,
            String addressLocality,
            String addressCountry,
            Long uprn,
            String validFrom,
            String validUntil,
            String subBuildingName,
            String organisationName,
            String dependentStreetName,
            String doubleDependentAddressLocality,
            String dependentAddressLocality) {
        var postalAddress = new PostalAddress();
        postalAddress.setBuildingNumber(buildingNumber);
        postalAddress.setBuildingName(buildingName);
        postalAddress.setStreetName(streetName);
        postalAddress.setPostalCode(postalCode);
        postalAddress.setAddressLocality(addressLocality);
        postalAddress.setAddressCountry(addressCountry);
        postalAddress.setUprn(uprn);
        postalAddress.setValidFrom(validFrom);
        postalAddress.setValidUntil(validUntil);
        postalAddress.setSubBuildingName(subBuildingName);
        postalAddress.setOrganisationName(organisationName);
        postalAddress.setDependentStreetName(dependentStreetName);
        postalAddress.setDependentAddressLocality(dependentAddressLocality);
        postalAddress.setDoubleDependentAddressLocality(doubleDependentAddressLocality);

        return postalAddress;
    }
}
