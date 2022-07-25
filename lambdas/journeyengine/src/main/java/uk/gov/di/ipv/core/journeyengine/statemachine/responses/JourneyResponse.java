package uk.gov.di.ipv.core.journeyengine.statemachine.responses;

import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.service.ConfigurationService;

import java.util.Map;

@ExcludeFromGeneratedCoverageReport
public class JourneyResponse implements JourneyStepResponse {

    private String journeyStepId;

    public JourneyResponse() {}

    public JourneyResponse(String journeyStepId) {
        this.journeyStepId = journeyStepId;
    }

    public String getJourneyStepId() {
        return journeyStepId;
    }

    public void setJourneyStepId(String journeyStepId) {
        this.journeyStepId = journeyStepId;
    }

    public Map<String, String> value(ConfigurationService configurationService) {
        return value(journeyStepId);
    }

    public Map<String, String> value(String id) {
        return Map.of("journey", id);
    }
}
