package uk.gov.di.ipv.core.processjourneyevent.statemachine.stepresponses;

import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

class ProcessStepResponseTest {

    @Test
    void valueReturnsCorrectJourneyResponse() {
        ProcessStepResponse processStepResponse =
                new ProcessStepResponse(
                        "a-process-lambda",
                        Map.of("input1", "Windom Earle", "input2", 315),
                        "is-mitigation-start");

        Map<String, Object> expectedValue =
                Map.of(
                        "journey",
                        "/journey/a-process-lambda?mitigationStart=is-mitigation-start",
                        "lambdaInput",
                        Map.of("input1", "Windom Earle", "input2", 315));
        assertEquals(expectedValue, processStepResponse.value());
    }
}
