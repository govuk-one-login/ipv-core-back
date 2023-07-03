package uk.gov.di.ipv.core.processjourneystep.statemachine.responses;

import org.junit.jupiter.api.Test;
import uk.gov.di.ipv.core.library.service.ConfigService;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;

public class JourneyResponseTest {

    public static final JourneyResponse JOURNEY_RESPONSE = new JourneyResponse("aJourneyStepId");

    @Test
    void valueWithConfigServiceReturnsCorrectJourneyResponse() {
        assertEquals(
                Map.of("journey", "aJourneyStepId"),
                JOURNEY_RESPONSE.value(mock(ConfigService.class)));
    }

    @Test
    void valueWithStringReturnsCorrectJourneyResponse() {
        assertEquals(
                Map.of("journey", "overriddenJourneyStepId"),
                JOURNEY_RESPONSE.value("overriddenJourneyStepId"));
    }
}
