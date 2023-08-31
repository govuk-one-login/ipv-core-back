package uk.gov.di.ipv.core.processjourneyevent.statemachine.stepresponses;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Map;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class ProcessStepResponse implements StepResponse {
    public static final String PROCESS = "process";
    public static final String LAMBDA_INPUT = "lambdaInput";
    private String lambda;
    private Map<String, Object> lambdaInput;

    @Override
    public Map<String, Object> value() {
        return Map.of(
                PROCESS, lambda,
                LAMBDA_INPUT, lambdaInput);
    }
}
