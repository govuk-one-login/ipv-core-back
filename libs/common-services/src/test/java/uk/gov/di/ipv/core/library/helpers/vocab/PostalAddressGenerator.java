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
        return PostalAddress.builder()
                .withBuildingNumber(buildingNumber)
                .withBuildingName(buildingName)
                .withStreetName(streetName)
                .withPostalCode(postalCode)
                .withAddressLocality(addressLocality)
                .withAddressCountry(addressCountry)
                .withUprn(uprn)
                .withValidFrom(validFrom)
                .withValidUntil(validUntil)
                .build();
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

        return PostalAddress.builder()
                .withBuildingNumber(buildingNumber)
                .withBuildingName(buildingName)
                .withStreetName(streetName)
                .withPostalCode(postalCode)
                .withAddressLocality(addressLocality)
                .withAddressCountry(addressCountry)
                .withUprn(uprn)
                .withValidFrom(validFrom)
                .withValidUntil(validUntil)
                .withSubBuildingName(subBuildingName)
                .withOrganisationName(organisationName)
                .withDependentStreetName(dependentStreetName)
                .withDependentAddressLocality(dependentAddressLocality)
                .withDoubleDependentAddressLocality(doubleDependentAddressLocality)
                .build();
    }
}
