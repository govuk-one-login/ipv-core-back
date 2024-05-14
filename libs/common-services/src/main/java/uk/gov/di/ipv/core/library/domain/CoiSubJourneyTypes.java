package uk.gov.di.ipv.core.library.domain;

import lombok.Getter;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@Getter
@ExcludeFromGeneratedCoverageReport
public enum CoiSubJourneyTypes {
    GIVEN_NAMES_ONLY("given-names-only"),
    FAMILY_NAME_ONLY("family-name-only"),
    ADDRESS_ONLY("address-only"),

    GIVEN_NAMES_AND_ADDRESS("given-names-and-address"),
    FAMILY_NAME_AND_ADDRESS("family-name-and-address");

    private final String path;

    CoiSubJourneyTypes(String path) {
        this.path = path;
    }
}
