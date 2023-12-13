package uk.gov.di.ipv.core.processjourneyevent.statemachine.stepresponses;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.util.Map;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class JourneyStepResponse implements StepResponse {
    private String journeyStepId;
    @Getter private Boolean mitigationStart;

    public Map<String, Object> value() {
        return Map.of("journey", journeyStepId);
    }
}
