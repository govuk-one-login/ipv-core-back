package uk.gov.di.ipv.core.processjourneystep.statemachine;

import org.junit.jupiter.api.Test;
import uk.gov.di.ipv.core.processjourneystep.statemachine.exceptions.UnknownStateException;
import uk.gov.di.ipv.core.processjourneystep.statemachine.responses.JourneyContext;
import uk.gov.di.ipv.core.processjourneystep.statemachine.states.BasicState;
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
        State endState = new BasicState();

        State startingState = mock(BasicState.class);
        when(startingState.transition("event", "startState", journeyContext)).thenReturn(endState);

        StateMachineInitializer mockStateMachineInitializer = mock(StateMachineInitializer.class);
        when(mockStateMachineInitializer.initialize())
                .thenReturn(Map.of("START_STATE", startingState));

        StateMachine stateMachine = new StateMachine(mockStateMachineInitializer);

        assertEquals(endState, stateMachine.transition("START_STATE", "event", journeyContext));
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
}
