package uk.gov.di.ipv.core.library.domain;

import lombok.Getter;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

import java.util.stream.Stream;

@Getter
@ExcludeFromGeneratedCoverageReport
public enum CoiSubjourneyType {
    REVERIFICATION("reverification"),
    ADDRESS_ONLY("address-only"),

    GIVEN_NAMES_ONLY("given-names-only"),
    FAMILY_NAME_ONLY("family-name-only"),

    GIVEN_NAMES_AND_ADDRESS("given-names-and-address"),
    FAMILY_NAME_AND_ADDRESS("family-name-and-address");

    private final String path;

    CoiSubjourneyType(String path) {
        this.path = path;
    }

    public static boolean isCoiSubjourneyEvent(String journeyEvent) {
        return Stream.of(CoiSubjourneyType.values())
                .anyMatch(subjourney -> subjourney.getPath().equals(journeyEvent));
    }

    public static CoiSubjourneyType fromString(String text) {
        for (CoiSubjourneyType journeyType : CoiSubjourneyType.values()) {
            if (journeyType.path.equalsIgnoreCase(text)) {
                return journeyType;
            }
        }

        throw new IllegalArgumentException(
                String.format("No constant for CoiSubjourneyType found for value: %s ", text));
    }
}
