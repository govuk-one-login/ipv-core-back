package uk.gov.di.ipv.core.processjourneystep.statemachine;

import org.junit.jupiter.api.Test;
import uk.gov.di.ipv.core.processjourneystep.statemachine.exceptions.UnknownStateException;
import uk.gov.di.ipv.core.processjourneystep.statemachine.responses.JourneyContext;
import uk.gov.di.ipv.core.processjourneystep.statemachine.responses.JourneyResponse;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class StateMachineTest {

    @Test
    void transitionShouldReturnStateMachineResultFromAppropriateState() throws Exception {
        JourneyContext journeyContext = JourneyContext.emptyContext();
        StateMachineResult expectedStateMachineResult =
                new StateMachineResult(new State("END_STATE"), new JourneyResponse());

        State startingState = mock(State.class);
        when(startingState.transition("event", journeyContext))
                .thenReturn(expectedStateMachineResult);

        StateMachineInitializer mockStateMachineInitializer = mock(StateMachineInitializer.class);
        when(mockStateMachineInitializer.initialize())
                .thenReturn(Map.of("START_STATE", startingState));

        StateMachine stateMachine = new StateMachine(mockStateMachineInitializer);

        assertEquals(
                expectedStateMachineResult,
                stateMachine.transition("START_STATE", "event", journeyContext));
    }

    @Test
    void transitionShouldThrowIfGivenAnUnknownState() throws Exception {
        StateMachineInitializer mockStateMachineInitializer = mock(StateMachineInitializer.class);
        when(mockStateMachineInitializer.initialize())
                .thenReturn(Map.of("START_STATE", new State("START_STATE")));

        StateMachine stateMachine = new StateMachine(mockStateMachineInitializer);

        assertThrows(
                UnknownStateException.class,
                () ->
                        stateMachine.transition(
                                "UNKNOWN_STATE", "event", JourneyContext.emptyContext()));
    }
}
