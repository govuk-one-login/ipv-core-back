package uk.gov.di.ipv.core.journeyengine.statemachine.responses;

import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.service.ConfigurationService;

import java.util.Map;

@ExcludeFromGeneratedCoverageReport
public class PageResponse implements JourneyStepResponse {

    private String pageId;

    public PageResponse() {}

    public PageResponse(String pageId) {
        this.pageId = pageId;
    }

    public String getPageId() {
        return pageId;
    }

    public void setPageId(String pageId) {
        this.pageId = pageId;
    }

    public Map<String, String> value(ConfigurationService configurationService) {
        return value(pageId);
    }

    public Map<String, String> value(String id) {
        return Map.of("page", id);
    }
}
