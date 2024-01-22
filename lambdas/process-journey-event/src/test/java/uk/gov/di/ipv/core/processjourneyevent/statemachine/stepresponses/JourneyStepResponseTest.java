package uk.gov.di.ipv.core.processjourneyevent.statemachine.stepresponses;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static uk.gov.di.ipv.core.library.domain.IpvJourneyTypes.IPV_CORE_MAIN_JOURNEY;

public class JourneyStepResponseTest {

    public static final JourneyStepResponse JOURNEY_RESPONSE =
            new JourneyStepResponse(IPV_CORE_MAIN_JOURNEY, "INITIAL", null);

    @Test
    void valueThrowsIllegalStateException() {
        assertThrows(IllegalStateException.class, JOURNEY_RESPONSE::value);
    }
}
