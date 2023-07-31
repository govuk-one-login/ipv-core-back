package uk.gov.di.ipv.core.processjourneystep.statemachine;

import org.junit.jupiter.api.Test;
import uk.gov.di.ipv.core.processjourneystep.statemachine.exceptions.UnknownStateException;
import uk.gov.di.ipv.core.processjourneystep.statemachine.responses.JourneyContext;
import uk.gov.di.ipv.core.processjourneystep.statemachine.states.BasicState;
import uk.gov.di.ipv.core.processjourneystep.statemachine.states.NestedJourneyInvokeState;
import uk.gov.di.ipv.core.processjourneystep.statemachine.states.State;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class StateMachineTest {

    @Test
    void transitionShouldReturnAppropriateState() throws Exception {
        JourneyContext journeyContext = JourneyContext.emptyContext();
        State expectedEndState = new BasicState();

        State startingState = mock(BasicState.class);
        when(startingState.transition("event", "START_STATE", journeyContext))
                .thenReturn(expectedEndState);

        StateMachineInitializer mockStateMachineInitializer = mock(StateMachineInitializer.class);
        when(mockStateMachineInitializer.initialize())
                .thenReturn(Map.of("START_STATE", startingState));

        StateMachine stateMachine = new StateMachine(mockStateMachineInitializer);

        State transitionedState = stateMachine.transition("START_STATE", "event", journeyContext);

        assertEquals(expectedEndState, transitionedState);
    }

    @Test
    void transitionShouldThrowIfGivenAnUnknownState() throws Exception {
        StateMachineInitializer mockStateMachineInitializer = mock(StateMachineInitializer.class);
        when(mockStateMachineInitializer.initialize())
                .thenReturn(Map.of("START_STATE", new BasicState()));

        StateMachine stateMachine = new StateMachine(mockStateMachineInitializer);

        assertThrows(
                UnknownStateException.class,
                () ->
                        stateMachine.transition(
                                "UNKNOWN_STATE", "event", JourneyContext.emptyContext()));
    }

    @Test
    void transitionShouldTransitionIntoNestedJourneyInvokeState() throws Exception {
        JourneyContext journeyContext = JourneyContext.emptyContext();
        State expectedNestedEndState = new BasicState();
        State nestedJourneyInvokeState = mock(NestedJourneyInvokeState.class);
        when(nestedJourneyInvokeState.transition("event", "START_STATE", journeyContext))
                .thenReturn(expectedNestedEndState);

        State startingState = mock(BasicState.class);
        when(startingState.transition("event", "START_STATE", journeyContext))
                .thenReturn(nestedJourneyInvokeState);

        StateMachineInitializer mockStateMachineInitializer = mock(StateMachineInitializer.class);
        when(mockStateMachineInitializer.initialize())
                .thenReturn(Map.of("START_STATE", startingState));

        StateMachine stateMachine = new StateMachine(mockStateMachineInitializer);

        State transitionState = stateMachine.transition("START_STATE", "event", journeyContext);

        assertEquals(expectedNestedEndState, transitionState);
    }

    @Test
    void transitionShouldHandleNestedStateName() throws Exception {
        JourneyContext journeyContext = JourneyContext.emptyContext();
        State expectedEndState = new BasicState();

        State startingState = mock(NestedJourneyInvokeState.class);
        when(startingState.transition("event", "START_STATE/NESTED_JOURNEY", journeyContext))
                .thenReturn(expectedEndState);

        StateMachineInitializer mockStateMachineInitializer = mock(StateMachineInitializer.class);
        when(mockStateMachineInitializer.initialize())
                .thenReturn(Map.of("START_STATE", startingState));

        StateMachine stateMachine = new StateMachine(mockStateMachineInitializer);

        State transitionedState =
                stateMachine.transition("START_STATE/NESTED_JOURNEY", "event", journeyContext);

        assertEquals(expectedEndState, transitionedState);
    }
}
