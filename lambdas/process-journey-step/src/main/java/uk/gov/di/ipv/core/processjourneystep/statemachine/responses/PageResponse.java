package uk.gov.di.ipv.core.processjourneystep.statemachine.responses;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.service.ConfigurationService;

import java.util.Map;

@ExcludeFromGeneratedCoverageReport
@Data
@NoArgsConstructor
@AllArgsConstructor
public class PageResponse implements JourneyStepResponse {

    private String pageId;

    public Map<String, Object> value(ConfigurationService configurationService) {
        return value(pageId);
    }

    public Map<String, Object> value(String id) {
        return Map.of("page", id);
    }
}
