package uk.gov.di.ipv.core.processjourneyevent.statemachine.stepresponses;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

import java.util.Map;

@ExcludeFromGeneratedCoverageReport
@NoArgsConstructor
@AllArgsConstructor
@Data
public class CriResponse implements JourneyStepResponse {

    public static final String CRI_JOURNEY_TEMPLATE = "/journey/cri/build-oauth-request/%s";

    private String criId;

    public Map<String, Object> value() {
        return Map.of("journey", String.format(CRI_JOURNEY_TEMPLATE, criId));
    }
}
