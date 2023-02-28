package uk.gov.di.ipv.core.processjourneystep.statemachine.responses;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.config.ConfigurationVariable;
import uk.gov.di.ipv.core.library.service.ConfigService;

import java.util.Map;

@ExcludeFromGeneratedCoverageReport
@NoArgsConstructor
@AllArgsConstructor
@Data
public class CriResponse implements JourneyStepResponse {

    private static final String CRI_START_JOURNEY = "/journey/cri/start/%s";

    private String criId;

    public Map<String, Object> value(ConfigService configService) {
        String ssmCriId = configService.getSsmParameter(ConfigurationVariable.valueOf(criId));
        return value(String.format(CRI_START_JOURNEY, ssmCriId));
    }

    public Map<String, Object> value(String id) {
        return Map.of("journey", id);
    }
}
