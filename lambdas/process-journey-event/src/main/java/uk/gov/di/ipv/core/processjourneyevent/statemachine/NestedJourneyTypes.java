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
    APP_DOC_CHECK("app-doc-check"),
    KBVS("kbvs"),
    STRATEGIC_APP_HANDLE_RESULT("strategic-app-handle-result"),
    STRATEGIC_APP_TRIAGE("strategic-app-triage"),
    WEB_DL_OR_PASSPORT("web-dl-or-passport"),
    F2F_FAILED("f2f-failed");

    private final String journeyName;

    NestedJourneyTypes(String journeyName) {
        this.journeyName = journeyName;
    }
}
