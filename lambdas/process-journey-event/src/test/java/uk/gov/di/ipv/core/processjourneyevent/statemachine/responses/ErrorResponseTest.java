package uk.gov.di.ipv.core.processjourneyevent.statemachine.responses;

import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class ErrorResponseTest {

    public static final ErrorResponse ERROR_RESPONSE = new ErrorResponse("aPageId", "500");

    @Test
    void valueReturnsCorrectResponse() {
        assertEquals(
                Map.of("type", "error", "page", "aPageId", "statusCode", 500),
                ERROR_RESPONSE.value());
    }
}
