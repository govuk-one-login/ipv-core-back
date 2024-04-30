package uk.gov.di.ipv.core.library.domain;

import lombok.Getter;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

import java.util.List;

@Getter
@ExcludeFromGeneratedCoverageReport
public enum CoiSubjourneyTypes {
    // Making changes to this enum? Let the data team know. Changes here will cause changes to the
    // IPV_SUBJOURNEY_START audit event, which they consume

    ADDRESS_ONLY("address-only"),

    GIVEN_NAMES_ONLY("given-names-only"),
    FAMILY_NAME_ONLY("family-name-only"),

    GIVEN_NAMES_AND_ADDRESS("given-names-and-address"),
    FAMILY_NAME_AND_ADDRESS("family-name-and-address");

    private final String path;

    CoiSubjourneyTypes(String path) {
        this.path = path;
    }

    public static boolean isCoiSubjourneyEvent(String journeyEvent) {
        return List.of(
                        ADDRESS_ONLY.getPath(),
                        GIVEN_NAMES_ONLY.getPath(),
                        GIVEN_NAMES_AND_ADDRESS.getPath(),
                        FAMILY_NAME_ONLY.getPath(),
                        FAMILY_NAME_AND_ADDRESS.getPath())
                .contains(journeyEvent);
    }

    public static CoiSubjourneyTypes fromString(String text) {
        for (CoiSubjourneyTypes journeyType : CoiSubjourneyTypes.values()) {
            if (journeyType.path.equalsIgnoreCase(text)) {
                return journeyType;
            }
        }

        throw new IllegalArgumentException(
                String.format("No constant for CoiSubjourneyTypes found for value: %s ", text));
    }
}
