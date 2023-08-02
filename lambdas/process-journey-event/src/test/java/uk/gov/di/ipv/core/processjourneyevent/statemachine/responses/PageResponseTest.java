package uk.gov.di.ipv.core.processjourneyevent.statemachine.responses;

import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class PageResponseTest {

    public static final PageResponse PAGE_RESPONSE = new PageResponse("aPageId");

    @Test
    void valueReturnsCorrectPageResponse() {
        assertEquals(Map.of("page", "aPageId"), PAGE_RESPONSE.value());
    }
}
