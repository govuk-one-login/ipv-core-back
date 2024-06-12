package uk.gov.di.ipv.core.processjourneyevent.statemachine;

import org.junit.jupiter.api.Test;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.exceptions.UnknownStateException;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.states.BasicState;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.states.NestedJourneyInvokeState;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.states.State;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.stepresponses.JourneyContext;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class StateMachineTest {
    private static final JourneyContext JOURNEY_CONTEXT =
            new JourneyContext(mock(ConfigService.class));

    @Test
    void transitionShouldReturnAppropriateState() throws Exception {
        var expectedResult = new TransitionResult(new BasicState());

        State startingState = mock(BasicState.class);
        when(startingState.transition("event", "START_STATE", JOURNEY_CONTEXT))
                .thenReturn(expectedResult);

        StateMachineInitializer mockStateMachineInitializer = mock(StateMachineInitializer.class);
        when(mockStateMachineInitializer.initialize())
                .thenReturn(Map.of("START_STATE", startingState));

        StateMachine stateMachine = new StateMachine(mockStateMachineInitializer);

        var actualResult = stateMachine.transition("START_STATE", "event", JOURNEY_CONTEXT, null);

        assertEquals(expectedResult, actualResult);
    }

    @Test
    void transitionShouldThrowIfGivenAnUnknownState() throws Exception {
        StateMachineInitializer mockStateMachineInitializer = mock(StateMachineInitializer.class);
        when(mockStateMachineInitializer.initialize())
                .thenReturn(Map.of("START_STATE", new BasicState()));

        StateMachine stateMachine = new StateMachine(mockStateMachineInitializer);

        assertThrows(
                UnknownStateException.class,
                () -> stateMachine.transition("UNKNOWN_STATE", "event", JOURNEY_CONTEXT, null));
    }

    @Test
    void transitionShouldTransitionIntoNestedJourneyInvokeState() throws Exception {
        var expectedResult = new TransitionResult(new BasicState());
        State nestedJourneyInvokeState = mock(NestedJourneyInvokeState.class);
        when(nestedJourneyInvokeState.transition("event", "START_STATE", JOURNEY_CONTEXT))
                .thenReturn(expectedResult);

        State startingState = mock(BasicState.class);
        when(startingState.transition("event", "START_STATE", JOURNEY_CONTEXT))
                .thenReturn(new TransitionResult(nestedJourneyInvokeState));

        StateMachineInitializer mockStateMachineInitializer = mock(StateMachineInitializer.class);
        when(mockStateMachineInitializer.initialize())
                .thenReturn(Map.of("START_STATE", startingState));

        StateMachine stateMachine = new StateMachine(mockStateMachineInitializer);

        var actualResult = stateMachine.transition("START_STATE", "event", JOURNEY_CONTEXT, null);

        assertEquals(expectedResult, actualResult);
    }

    @Test
    void transitionShouldHandleNestedStateName() throws Exception {
        var expectedResult = new TransitionResult(new BasicState());

        State startingState = mock(NestedJourneyInvokeState.class);
        when(startingState.transition("event", "START_STATE/NESTED_JOURNEY", JOURNEY_CONTEXT))
                .thenReturn(expectedResult);

        StateMachineInitializer mockStateMachineInitializer = mock(StateMachineInitializer.class);
        when(mockStateMachineInitializer.initialize())
                .thenReturn(Map.of("START_STATE", startingState));

        StateMachine stateMachine = new StateMachine(mockStateMachineInitializer);

        var actualResult =
                stateMachine.transition(
                        "START_STATE/NESTED_JOURNEY", "event", JOURNEY_CONTEXT, null);

        assertEquals(expectedResult, actualResult);
    }
}
