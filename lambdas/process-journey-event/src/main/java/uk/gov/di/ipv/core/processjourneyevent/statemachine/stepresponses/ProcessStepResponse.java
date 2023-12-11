package uk.gov.di.ipv.core.processjourneyevent.statemachine.stepresponses;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.util.HashMap;
import java.util.Map;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class ProcessStepResponse implements StepResponse {
    private static final String JOURNEY = "journey";
    private static final String LAMBDA_INPUT = "lambdaInput";
    private static final String JOURNEY_TEMPLATE = "/journey/%s";
    private String lambda;
    private Map<String, Object> lambdaInput;
    @Getter private Boolean mitigationStart;

    @Override
    public Map<String, Object> value() {
        HashMap<String, Object> response = new HashMap<>();
        response.put(JOURNEY, String.format(JOURNEY_TEMPLATE, lambda));
        response.put(LAMBDA_INPUT, lambdaInput);

        return response;
    }
}
