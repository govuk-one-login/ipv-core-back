package uk.gov.di.ipv.core.journeyengine.domain;

import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@ExcludeFromGeneratedCoverageReport
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

    public static class Builder {
        private PageResponse pageResponse;
        private JourneyResponse journeyResponse;

        public Builder setPageResponse(PageResponse pageResponse) {
            this.pageResponse = pageResponse;
            return this;
        }

        public Builder setJourneyResponse(JourneyResponse journeyResponse) {
            this.journeyResponse = journeyResponse;
            return this;
        }

        public JourneyEngineResult build() {
            return new JourneyEngineResult(pageResponse, journeyResponse);
        }
    }
}
