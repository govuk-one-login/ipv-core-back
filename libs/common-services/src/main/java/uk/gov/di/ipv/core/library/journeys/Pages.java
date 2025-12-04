package uk.gov.di.ipv.core.library.journeys;

import lombok.Getter;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@ExcludeFromGeneratedCoverageReport
public enum Pages {
    PROBLEM_DIFFERENT_BROWSER("problem-different-browser");

    @Getter private final String pageId;

    Pages(String pageId) {
        this.pageId = pageId;
    }
}
