package uk.gov.di.ipv.core.processjourneyevent.statemachine;

import lombok.Getter;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@Getter
@ExcludeFromGeneratedCoverageReport
public enum NestedJourneyTypes {
    // When a new nested-journey is added, it needs to be added to this enum
    // as the statemachine will load only these files when initialising.
    // The NESTED_JOURNEY_TYPES constant in the journey map visualisation
    // will also need to be updated.
    ADDRESS_AND_FRAUD("address-and-fraud"),
    KBVS("kbvs"),
    STRATEGIC_APP_TRIAGE("strategic-app-triage"),
    WEB_DL_OR_PASSPORT("web-dl-or-passport"),
    DCMAW_DRIVING_LICENCE("dcmaw-driving-licence");

    private final String journeyName;

    NestedJourneyTypes(String journeyName) {
        this.journeyName = journeyName;
    }
}
