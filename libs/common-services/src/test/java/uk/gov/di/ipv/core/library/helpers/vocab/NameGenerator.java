package uk.gov.di.ipv.core.library.helpers.vocab;

import uk.gov.di.model.Name;
import uk.gov.di.model.NamePart;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Stream;

public class NameGenerator {
    private NameGenerator() {}

    public static Name createName(List<NamePart> nameParts) {
        return Name.builder().withNameParts(nameParts).build();
    }

    public static Name createName(String givenName, String familyName) {
        return createName(new String[] {givenName}, new String[] {familyName});
    }

    public static Name createName(String[] givenNames, String[] familyNames) {
        var givenNameParts =
                Arrays.stream(givenNames)
                        .map(
                                gn ->
                                        NamePartGenerator.createNamePart(
                                                gn, NamePart.NamePartType.GIVEN_NAME));
        var familyNameParts =
                Arrays.stream(familyNames)
                        .map(
                                fn ->
                                        NamePartGenerator.createNamePart(
                                                fn, NamePart.NamePartType.FAMILY_NAME));
        var allNameParts = Stream.concat(givenNameParts, familyNameParts).toList();

        return createName(allNameParts);
    }

    public static Name createName(String givenName, String[] familyNames) {
        return createName(new String[] {givenName}, familyNames);
    }

    public static Name createName(String[] givenNames, String familyName) {
        return createName(givenNames, new String[] {familyName});
    }

    public static class NamePartGenerator {
        private NamePartGenerator() {}

        public static NamePart createNamePart(String value, NamePart.NamePartType type) {
            return NamePart.builder().withValue(value).withType(type).build();
        }
    }
}
