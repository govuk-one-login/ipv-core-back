package uk.gov.di.ipv.core.processjourneystep.statemachine.responses;

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
