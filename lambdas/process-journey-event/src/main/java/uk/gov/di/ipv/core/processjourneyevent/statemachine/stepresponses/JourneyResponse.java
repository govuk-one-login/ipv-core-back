package uk.gov.di.ipv.core.processjourneyevent.statemachine.stepresponses;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Map;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class JourneyResponse implements JourneyStepResponse {

    private String journeyStepId;

    public Map<String, Object> value() {
        return Map.of("journey", journeyStepId);
    }
}
