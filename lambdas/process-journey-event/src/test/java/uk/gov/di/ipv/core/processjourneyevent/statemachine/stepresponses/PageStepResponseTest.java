package uk.gov.di.ipv.core.processjourneyevent.statemachine.stepresponses;

import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class PageStepResponseTest {

    public static final PageStepResponse PAGE_RESPONSE =
            new PageStepResponse("aPageId", "testContext", false, Map.of("reason", "testContext"));

    @Test
    void valueReturnsCorrectPageResponse() {
        assertEquals(
                Map.of(
                        "page",
                        "aPageId",
                        "context",
                        "testContext",
                        "skipBack",
                        false,
                        "pageContext",
                        Map.of("reason", "testContext")),
                PAGE_RESPONSE.value());
    }
}
