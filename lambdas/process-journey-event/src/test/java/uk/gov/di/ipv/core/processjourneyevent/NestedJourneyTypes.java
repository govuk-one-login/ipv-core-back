package uk.gov.di.ipv.core.processjourneyevent;

import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@ExcludeFromGeneratedCoverageReport
public enum NestedJourneyTypes {
    NESTED_JOURNEY_DEFINITION("nested-journey-definition"),
    DOUBLY_NESTED_JOURNEY_DEFINITION("doubly-nested-definition");

    private final String journeyName;

    NestedJourneyTypes(String journeyName) {
        this.journeyName = journeyName;
    }

    public String getJourneyName() {
        return journeyName;
    }
}
