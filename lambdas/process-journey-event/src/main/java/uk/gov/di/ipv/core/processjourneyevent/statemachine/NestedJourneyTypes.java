package uk.gov.di.ipv.core.processjourneyevent.statemachine;

import lombok.Getter;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@Getter
@ExcludeFromGeneratedCoverageReport
public enum NestedJourneyTypes {
    // When a new nested-journey is added, it needs to be added here
    // as the statemachine will look here when initialising
    ADDRESS_AND_FRAUD("address-and-fraud"),
    KBVS("kbvs"),
    STRATEGIC_APP_TRIAGE("strategic-app-triage"),
    WEB_DL_OR_PASSPORT("web-dl-or-passport");

    private final String journeyName;

    NestedJourneyTypes(String journeyName) {
        this.journeyName = journeyName;
    }
}
