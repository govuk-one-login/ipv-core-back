package uk.gov.di.ipv.core.processjourneyevent.statemachine.events;

import org.junit.jupiter.api.Test;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.TransitionResult;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.exceptions.UnknownEventException;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.states.BasicState;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.states.State;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.stepresponses.JourneyContext;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class ExitNestedJourneyEventTest {
    private static final JourneyContext JOURNEY_CONTEXT =
            new JourneyContext(mock(ConfigService.class));

    @Test
    void resolveShouldResolveEventFromNestedJourneyExitEvents() throws UnknownEventException {
        var expectedResult = new TransitionResult(new BasicState());
        BasicEvent nestedJourneyExitEvent = mock(BasicEvent.class);
        when(nestedJourneyExitEvent.resolve(any(JourneyContext.class))).thenReturn(expectedResult);

        ExitNestedJourneyEvent exitNestedJourneyEvent = new ExitNestedJourneyEvent();
        exitNestedJourneyEvent.setExitEventToEmit("exiting");
        exitNestedJourneyEvent.setNestedJourneyExitEvents(
                Map.of("exiting", nestedJourneyExitEvent));

        assertEquals(expectedResult, exitNestedJourneyEvent.resolve(JOURNEY_CONTEXT));
    }

    @Test
    void resolveShouldThrowIfEventNotFoundInNestedJourneyExitEvents() {
        ExitNestedJourneyEvent exitNestedJourneyEvent = new ExitNestedJourneyEvent();
        exitNestedJourneyEvent.setNestedJourneyExitEvents(Map.of("exiting", new BasicEvent()));
        exitNestedJourneyEvent.setExitEventToEmit("not-found");

        assertThrows(
                UnknownEventException.class, () -> exitNestedJourneyEvent.resolve(JOURNEY_CONTEXT));
    }

    @Test
    void initializeShouldThrowAnUnsupportedOperationException() {
        ExitNestedJourneyEvent exitNestedJourneyEvent = new ExitNestedJourneyEvent();
        Map<String, State> emptyMap = Map.of();
        assertThrows(
                UnsupportedOperationException.class,
                () -> exitNestedJourneyEvent.initialize("name", emptyMap));
    }
}
