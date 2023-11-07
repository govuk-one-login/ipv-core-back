package uk.gov.di.ipv.core.processjourneyevent.statemachine.stepresponses;

import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

class ProcessStepResponseTest {

    @Test
    void valueReturnsCorrectJourneyResponse() {
        ProcessStepResponse processStepResponse =
                new ProcessStepResponse(
                        "a-process-lambda", Map.of("input1", "Windom Earle", "input2", 315));

        Map<String, Object> expectedValue =
                Map.of(
                        "journey",
                        "/journey/a-process-lambda",
                        "lambdaInput",
                        Map.of("input1", "Windom Earle", "input2", 315));
        assertEquals(expectedValue, processStepResponse.value());
    }
}
