package uk.gov.di.ipv.core.processjourneystep.statemachine.states;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.processjourneystep.statemachine.events.BasicEvent;
import uk.gov.di.ipv.core.processjourneystep.statemachine.exceptions.UnknownEventException;
import uk.gov.di.ipv.core.processjourneystep.statemachine.responses.JourneyContext;
import uk.gov.di.ipv.core.processjourneystep.statemachine.responses.JourneyResponse;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

@ExtendWith(MockitoExtension.class)
class BasicStateTest {
    @Mock private static ConfigService mockConfigService;

    @Test
    void transitionShouldReturnAStateWithAResponse() throws Exception {
        BasicState targetState = new BasicState();
        JourneyResponse journeyResponse = new JourneyResponse("stepId");
        targetState.setResponse(journeyResponse);

        BasicState currentState = new BasicState();
        BasicEvent currentToTargetEvent = new BasicEvent(mockConfigService);
        currentToTargetEvent.setTargetStateObj(targetState);
        currentState.setEvents(Map.of("next", currentToTargetEvent));

        BasicState transitionedState =
                (BasicState)
                        currentState.transition(
                                "next", "startState", JourneyContext.emptyContext());

        assertEquals(targetState, transitionedState);
        assertEquals(journeyResponse, transitionedState.getResponse());
    }

    @Test
    void transitionShouldUseEventsFromParentState() throws Exception {
        BasicEvent parentEvent = new BasicEvent(mockConfigService);
        BasicState parentEventTargetState = new BasicState();
        parentEvent.setTargetStateObj(parentEventTargetState);

        BasicState parentState = new BasicState();
        parentState.setEvents(Map.of("parent-event", parentEvent));

        BasicState currentState = new BasicState();
        currentState.setParentObj(parentState);

        State transitionedState =
                currentState.transition(
                        "parent-event", "startState", JourneyContext.emptyContext());

        assertEquals(parentEventTargetState, transitionedState);
    }

    @Test
    void transitionShouldReturnThisIfAttemptRecoveryEventReceived() throws Exception {
        State state = new BasicState();

        assertSame(
                state,
                state.transition("attempt-recovery", "startState", JourneyContext.emptyContext()));
    }

    @Test
    void transitionShouldThrowIfEventNotFound() {
        assertThrows(
                UnknownEventException.class,
                () ->
                        new BasicState()
                                .transition(
                                        "unknown-event",
                                        "startState",
                                        JourneyContext.emptyContext()));
    }

    @Test
    void toStringShouldReturnName() {
        BasicState state = new BasicState();
        state.setName("Bungle");

        assertEquals("Bungle", state.toString());
    }
}
