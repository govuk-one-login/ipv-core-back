package uk.gov.di.ipv.core.processjourneyevent.statemachine.stepresponses;

import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class JourneyStepResponseTest {

    public static final JourneyStepResponse JOURNEY_RESPONSE =
            new JourneyStepResponse("aJourneyStepId");

    @Test
    void valueReturnsCorrectJourneyResponse() {
        assertEquals(Map.of("journey", "aJourneyStepId"), JOURNEY_RESPONSE.value());
    }
}
