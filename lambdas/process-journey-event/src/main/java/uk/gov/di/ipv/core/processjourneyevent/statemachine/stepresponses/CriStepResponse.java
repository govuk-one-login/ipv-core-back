package uk.gov.di.ipv.core.processjourneyevent.statemachine.stepresponses;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import uk.gov.di.ipv.core.library.annotations.ExcludeFromGeneratedCoverageReport;

import java.util.Map;
import java.util.Objects;

@ExcludeFromGeneratedCoverageReport
@NoArgsConstructor
@AllArgsConstructor
@Data
public class CriStepResponse implements StepResponse {

    public static final String CRI_JOURNEY_TEMPLATE = "/journey/cri/build-oauth-request/%s";

    private String criId;
    private String scope;

    public Map<String, Object> value() {
        if (Objects.nonNull(scope)) {
            return Map.of("journey", String.format(CRI_JOURNEY_TEMPLATE, criId), "scope", scope);
        } else {
            return Map.of("journey", String.format(CRI_JOURNEY_TEMPLATE, criId));
        }
    }
}
