package uk.gov.di.ipv.core.journeyengine.domain;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

@ExcludeFromGeneratedCoverageReport
public class PageResponse {
    @JsonProperty private final String page;

    @JsonCreator
    public PageResponse(@JsonProperty(value = "page", required = true) String page) {
        this.page = page;
    }

    public String getPage() {
        return page;
    }
}
