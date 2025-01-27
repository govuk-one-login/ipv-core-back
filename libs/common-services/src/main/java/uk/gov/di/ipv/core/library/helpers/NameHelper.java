package uk.gov.di.ipv.core.library.helpers;

import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.model.Name;
import uk.gov.di.model.NamePart;

import java.util.ArrayList;
import java.util.Set;
import java.util.stream.Collectors;

public class NameHelper {

    @ExcludeFromGeneratedCoverageReport
    private NameHelper() {
        throw new IllegalStateException("Utility class");
    }

    public static Set<Name> deduplicateNames(Set<Name> names) {
        if (names == null) {
            return null;
        }

        var capitalisedFullNames = new ArrayList<String>();

        return names.stream()
                .filter(
                        name -> {
                            var capitalisedFullName = NameHelper.getFullName(name).toUpperCase();

                            if (!capitalisedFullNames.contains(capitalisedFullName)) {
                                capitalisedFullNames.add(capitalisedFullName);
                                return true;
                            }
                            return false;
                        })
                .collect(Collectors.toSet());
    }

    public static String getFullName(Name name) {
        var nameParts = name.getNameParts();

        String givenNames =
                nameParts.stream()
                        .filter(
                                namePart ->
                                        NamePart.NamePartType.GIVEN_NAME.equals(namePart.getType()))
                        .map(NamePart::getValue)
                        .collect(Collectors.joining(" "));

        String familyNames =
                nameParts.stream()
                        .filter(
                                namePart ->
                                        NamePart.NamePartType.FAMILY_NAME.equals(
                                                namePart.getType()))
                        .map(NamePart::getValue)
                        .collect(Collectors.joining(" "));

        return (givenNames + " " + familyNames).trim();
    }
}
