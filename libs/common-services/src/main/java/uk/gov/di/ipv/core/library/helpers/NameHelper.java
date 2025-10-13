package uk.gov.di.ipv.core.library.helpers;

import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.model.Name;
import uk.gov.di.model.NamePart;

import java.text.Normalizer;
import java.util.ArrayList;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

public class NameHelper {

    private static final Pattern DIACRITIC_CHECK_PATTERN = Pattern.compile("\\p{M}");
    private static final Pattern IGNORE_SOME_CHARACTERS_PATTERN = Pattern.compile("[\\s'’-]+");

    @ExcludeFromGeneratedCoverageReport
    private NameHelper() {
        throw new IllegalStateException("Utility class");
    }

    public static Set<Name> deduplicateNames(Set<Name> names) {
        if (names == null) {
            return Set.of();
        }

        var normalisedNames = new ArrayList<String>();

        return names.stream()
                .filter(
                        name -> {
                            var normalisedName = getNormalisedFullNameForComparison(name);

                            if (!normalisedNames.contains(normalisedName)) {
                                normalisedNames.add(normalisedName);
                                return true;
                            }
                            return false;
                        })
                .collect(Collectors.toSet());
    }

    public static String getNormalisedFullNameForComparison(Name name) {
        var nameParts = name.getNameParts();

        String givenNames =
                nameParts.stream()
                        .filter(
                                namePart ->
                                        NamePart.NamePartType.GIVEN_NAME.equals(namePart.getType()))
                        .map(NamePart::getValue)
                        .collect(Collectors.joining(" "))
                        .trim();

        String familyNames =
                nameParts.stream()
                        .filter(
                                namePart ->
                                        NamePart.NamePartType.FAMILY_NAME.equals(
                                                namePart.getType()))
                        .map(NamePart::getValue)
                        .collect(Collectors.joining(" "))
                        .trim();

        return (normaliseNameForComparison(givenNames)
                + " "
                + normaliseNameForComparison(familyNames));
    }

    public static String normaliseNameForComparison(String name) {
        var unicodeNormalisedName = Normalizer.normalize(name, Normalizer.Form.NFD);
        var diacriticRemovedName =
                DIACRITIC_CHECK_PATTERN.matcher(unicodeNormalisedName).replaceAll("");
        var specialCharactersRemovedName =
                IGNORE_SOME_CHARACTERS_PATTERN.matcher(diacriticRemovedName).replaceAll("");
        return specialCharactersRemovedName.toLowerCase();
    }
}
