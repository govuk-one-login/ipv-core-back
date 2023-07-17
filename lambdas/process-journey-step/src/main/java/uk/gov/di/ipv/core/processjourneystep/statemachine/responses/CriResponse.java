package uk.gov.di.ipv.core.processjourneystep.statemachine.responses;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;
import uk.gov.di.ipv.core.library.service.ConfigService;

import java.util.Map;

@ExcludeFromGeneratedCoverageReport
@NoArgsConstructor
@AllArgsConstructor
@Data
public class CriResponse implements JourneyStepResponse {

    public static final String CRI_JOURNEY_TEMPLATE = "/journey/cri/build-oauth-request/%s";

    private String criId;

    public Map<String, Object> value(ConfigService configService) {
        return value(String.format(CRI_JOURNEY_TEMPLATE, criId));
    }

    public Map<String, Object> value(String id) {
        return Map.of("journey", id);
    }
}
