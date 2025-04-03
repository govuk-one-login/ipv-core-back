package uk.gov.di.ipv.core.library.helpers.vocab;

import uk.gov.di.model.Name;
import uk.gov.di.model.NamePart;

import java.util.List;

public class NameGenerator {
    private NameGenerator() {}

    public static Name createName(List<NamePart> nameParts) {
        return Name.builder().withNameParts(nameParts).build();
    }

    public static Name createName(String givenName, String familyName) {
        return createName(
                List.of(
                        NamePartGenerator.createNamePart(
                                givenName, NamePart.NamePartType.GIVEN_NAME),
                        NamePartGenerator.createNamePart(
                                familyName, NamePart.NamePartType.FAMILY_NAME)));
    }

    public static class NamePartGenerator {
        private NamePartGenerator() {}

        public static NamePart createNamePart(String value, NamePart.NamePartType type) {
            return NamePart.builder().withValue(value).withType(type).build();
        }
    }
}
