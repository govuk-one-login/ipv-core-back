package uk.gov.di.ipv.core.processjourneystep.statemachine;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import uk.gov.di.ipv.core.processjourneystep.statemachine.events.BasicEvent;
import uk.gov.di.ipv.core.processjourneystep.statemachine.exceptions.UnknownEventException;
import uk.gov.di.ipv.core.processjourneystep.statemachine.responses.JourneyContext;
import uk.gov.di.ipv.core.processjourneystep.statemachine.responses.JourneyResponse;
import uk.org.webcompere.systemstubs.environment.EnvironmentVariables;
import uk.org.webcompere.systemstubs.jupiter.SystemStub;
import uk.org.webcompere.systemstubs.jupiter.SystemStubsExtension;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;

@ExtendWith(SystemStubsExtension.class)
class StateTest {

    @SystemStub private static EnvironmentVariables environmentVariables;

    @BeforeAll
    private static void beforeAll() {
        environmentVariables.set("IS_LOCAL", "true");
    }

    @Test
    void transitionShouldReturnAState() throws Exception {
        State targetState = new State();
        JourneyResponse journeyResponse = new JourneyResponse("stepId");
        targetState.setResponse(journeyResponse);

        State currentState = new State();
        BasicEvent currentToTargetEvent = new BasicEvent();
        currentToTargetEvent.setTargetStateObj(targetState);
        currentState.setEvents(Map.of("next", currentToTargetEvent));

        State transitionedState = currentState.transition("next", JourneyContext.emptyContext());

        assertEquals(targetState, transitionedState);
        assertEquals(journeyResponse, transitionedState.getResponse());
    }

    @Test
    void transitionShouldUseEventsFromParentState() throws Exception {
        BasicEvent parentEvent = new BasicEvent();
        State parentEventTargetState = new State();
        parentEvent.setTargetStateObj(parentEventTargetState);

        State parentState = new State();
        parentState.setEvents(Map.of("parent-event", parentEvent));

        State currentState = new State();
        currentState.setParentObj(parentState);

        State transitionedState =
                currentState.transition("parent-event", JourneyContext.emptyContext());

        assertEquals(parentEventTargetState, transitionedState);
    }

    @Test
    void transitionShouldReturnThisIfAttemptRecoveryEventReceived() throws Exception {
        State state = new State();

        assertSame(state, state.transition("attempt-recovery", JourneyContext.emptyContext()));
    }

    @Test
    void transitionShouldThrowIfEventNotFound() {
        assertThrows(
                UnknownEventException.class,
                () -> new State().transition("unknown-event", JourneyContext.emptyContext()));
    }

    @Test
    void toStringShouldReturnName() {
        State state = new State();
        state.setName("Bungle");

        assertEquals("Bungle", state.toString());
    }
}
