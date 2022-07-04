package uk.gov.di.ipv.core.journeyengine.domain;

import lombok.Builder;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.domain.JourneyResponse;

@ExcludeFromGeneratedCoverageReport
@Builder
public class JourneyEngineResult {
    private final PageResponse pageResponse;
    private final JourneyResponse journeyResponse;

    public JourneyEngineResult(PageResponse pageResponse, JourneyResponse journeyResponse) {
        this.pageResponse = pageResponse;
        this.journeyResponse = journeyResponse;
    }

    public PageResponse getPageResponse() {
        return pageResponse;
    }

    public JourneyResponse getJourneyResponse() {
        return journeyResponse;
    }
}
