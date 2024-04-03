package uk.gov.di.ipv.core.processjourneyevent.statemachine.states;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.events.BasicEvent;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.exceptions.UnknownEventException;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.stepresponses.JourneyContext;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.stepresponses.PageStepResponse;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

@ExtendWith(MockitoExtension.class)
class BasicStateTest {
    @Mock private ConfigService mockConfigService;
    @InjectMocks private JourneyContext journeyContext;

    @Test
    void transitionShouldReturnAStateWithAResponse() throws Exception {
        BasicState targetState = new BasicState();
        PageStepResponse stepResponse = new PageStepResponse("stepId", "context", null);
        targetState.setResponse(stepResponse);

        BasicState currentState = new BasicState();
        BasicEvent currentToTargetEvent = new BasicEvent();
        currentToTargetEvent.setTargetStateObj(targetState);
        currentState.setEvents(Map.of("next", currentToTargetEvent));

        BasicState transitionedState =
                (BasicState) currentState.transition("next", "startState", journeyContext);

        assertEquals(targetState, transitionedState);
        assertEquals(stepResponse, transitionedState.getResponse());
    }

    @Test
    void transitionShouldUseEventsFromParentState() throws Exception {
        BasicEvent parentEvent = new BasicEvent();
        BasicState parentEventTargetState = new BasicState();
        parentEvent.setTargetStateObj(parentEventTargetState);

        BasicState parentState = new BasicState();
        parentState.setEvents(Map.of("parent-event", parentEvent));

        BasicState currentState = new BasicState();
        currentState.setParentObj(parentState);

        State transitionedState =
                currentState.transition("parent-event", "startState", journeyContext);

        assertEquals(parentEventTargetState, transitionedState);
    }

    @Test
    void transitionShouldReturnThisIfAttemptRecoveryEventReceived() throws Exception {
        State state = new BasicState();

        assertSame(state, state.transition("attempt-recovery", "startState", journeyContext));
    }

    @Test
    void transitionShouldThrowIfEventNotFound() {
        assertThrows(
                UnknownEventException.class,
                () -> new BasicState().transition("unknown-event", "startState", journeyContext));
    }

    @Test
    void toStringShouldReturnName() {
        BasicState state = new BasicState();
        state.setName("Bungle");

        assertEquals("Bungle", state.toString());
    }
}
