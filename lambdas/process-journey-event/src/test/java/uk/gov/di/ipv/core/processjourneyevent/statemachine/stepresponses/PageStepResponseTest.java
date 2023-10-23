package uk.gov.di.ipv.core.processjourneyevent.statemachine.stepresponses;

import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class PageStepResponseTest {

    public static final PageStepResponse PAGE_RESPONSE = new PageStepResponse("aPageId", "test");

    @Test
    void valueReturnsCorrectPageResponse() {
        assertEquals(Map.of("page", "aPageId", "context", "test"), PAGE_RESPONSE.value());
    }
}
