package uk.gov.di.ipv.core.processjourneystep.statemachine.responses;

import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
import uk.gov.di.ipv.core.library.service.ConfigurationService;

import java.util.Map;

@ExcludeFromGeneratedCoverageReport
public class CriResponse implements JourneyStepResponse {

    private static final String CRI_START_JOURNEY = "/journey/cri/start/%s";

    private String criId;

    public CriResponse() {}

    public CriResponse(String criId) {
        this.criId = criId;
    }

    public String getCriId() {
        return criId;
    }

    public void setCriId(String criId) {
        this.criId = criId;
    }

    public Map<String, String> value(ConfigurationService configurationService) {
        String ssmCriId =
                configurationService.getSsmParameter(ConfigurationVariable.valueOf(criId));
        return value(String.format(CRI_START_JOURNEY, ssmCriId));
    }

    public Map<String, String> value(String id) {
        return Map.of("journey", id);
    }
}
