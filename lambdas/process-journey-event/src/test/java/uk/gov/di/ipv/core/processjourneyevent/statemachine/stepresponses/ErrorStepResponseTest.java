package uk.gov.di.ipv.core.processjourneyevent.statemachine.stepresponses;

import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class ErrorStepResponseTest {

    public static final ErrorStepResponse ERROR_RESPONSE = new ErrorStepResponse("aPageId", "500");

    @Test
    void valueReturnsCorrectResponse() {
        assertEquals(
                Map.of("type", "error", "page", "aPageId", "statusCode", 500),
                ERROR_RESPONSE.value());
    }
}
