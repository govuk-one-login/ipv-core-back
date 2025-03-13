package uk.gov.di.ipv.core.processjourneyevent.statemachine.events;

import org.junit.jupiter.api.Test;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.states.State;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertThrows;

class ExitNestedJourneyEventTest {
    @Test
    void initializeShouldThrowAnUnsupportedOperationException() {
        ExitNestedJourneyEvent exitNestedJourneyEvent = new ExitNestedJourneyEvent();
        Map<String, State> emptyStateMap = Map.of();
        Map<String, Event> emptyEventMap = Map.of();

        assertThrows(
                UnsupportedOperationException.class,
                () -> exitNestedJourneyEvent.initialize("name", emptyStateMap, emptyEventMap));
    }
}
