package uk.gov.di.ipv.core.processjourneyevent.statemachine;

import org.junit.jupiter.api.Test;
import uk.gov.di.ipv.core.library.domain.JourneyState;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.exceptions.UnknownStateException;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.states.BasicState;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.states.NestedJourneyDefinition;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.states.NestedJourneyInvokeState;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.states.State;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.stepresponses.JourneyContext;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.stepresponses.PageStepResponse;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.stepresponses.ProcessStepResponse;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.domain.IpvJourneyTypes.INITIAL_JOURNEY_SELECTION;

class StateMachineTest {
    private static final JourneyContext JOURNEY_CONTEXT =
            new JourneyContext(mock(ConfigService.class), "");

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

    @Test
    void getStateShouldReturnState() throws Exception {
        State stateOne = mock(BasicState.class);
        State stateTwo = mock(BasicState.class);
        State stateThree = mock(BasicState.class);

        StateMachineInitializer mockStateMachineInitializer = mock(StateMachineInitializer.class);
        when(mockStateMachineInitializer.initialize())
                .thenReturn(
                        Map.of(
                                "STATE_ONE",
                                stateOne,
                                "STATE_TWO",
                                stateTwo,
                                "STATE_THREE",
                                stateThree));

        StateMachine stateMachine = new StateMachine(mockStateMachineInitializer);

        assertEquals(stateTwo, stateMachine.getState("STATE_TWO"));
    }

    @Test
    void getStateShouldGetNestedState() throws Exception {
        State stateOne = mock(BasicState.class);
        NestedJourneyInvokeState stateTwo = new NestedJourneyInvokeState();
        State stateThree = mock(BasicState.class);

        State nestedStateOne = mock(BasicState.class);
        State nestedStateTwo = mock(BasicState.class);
        State nestedStateThree = mock(BasicState.class);

        var nestedJourneyDefinition = new NestedJourneyDefinition();
        nestedJourneyDefinition.setNestedJourneyStates(
                Map.of(
                        "NESTED_ONE",
                        nestedStateOne,
                        "NESTED_TWO",
                        nestedStateTwo,
                        "NESTED_THREE",
                        nestedStateThree));
        stateTwo.setNestedJourneyDefinition(nestedJourneyDefinition);

        StateMachineInitializer mockStateMachineInitializer = mock(StateMachineInitializer.class);
        when(mockStateMachineInitializer.initialize())
                .thenReturn(
                        Map.of(
                                "STATE_ONE",
                                stateOne,
                                "STATE_TWO_NESTED_INVOKE_STATE",
                                stateTwo,
                                "STATE_THREE",
                                stateThree));

        StateMachine stateMachine = new StateMachine(mockStateMachineInitializer);

        assertEquals(
                nestedStateThree,
                stateMachine.getState("STATE_TWO_NESTED_INVOKE_STATE/NESTED_THREE"));
    }

    @Test
    void getStateShouldGetDoublyNestedState() throws Exception {
        State stateOne = mock(BasicState.class);
        NestedJourneyInvokeState stateTwo = new NestedJourneyInvokeState();
        State stateThree = mock(BasicState.class);

        State nestedStateOne = mock(BasicState.class);
        State nestedStateTwo = mock(BasicState.class);
        NestedJourneyInvokeState nestedStateThree = new NestedJourneyInvokeState();

        State doublyNestedStateOne = mock(BasicState.class);
        State doublyNestedStateTwo = mock(BasicState.class);
        State doublyNestedStateThree = mock(BasicState.class);

        var nestedJourneyDefinition = new NestedJourneyDefinition();
        nestedJourneyDefinition.setNestedJourneyStates(
                Map.of(
                        "NESTED_ONE",
                        nestedStateOne,
                        "NESTED_TWO",
                        nestedStateTwo,
                        "NESTED_THREE_NESTED_INVOKE_STATE",
                        nestedStateThree));
        stateTwo.setNestedJourneyDefinition(nestedJourneyDefinition);

        var doublyNestedJourneyDefinition = new NestedJourneyDefinition();
        doublyNestedJourneyDefinition.setNestedJourneyStates(
                Map.of(
                        "DOUBLE_NESTED_ONE",
                        doublyNestedStateOne,
                        "DOUBLE_NESTED_TWO",
                        doublyNestedStateTwo,
                        "DOUBLE_NESTED_THREE",
                        doublyNestedStateThree));
        nestedStateThree.setNestedJourneyDefinition(doublyNestedJourneyDefinition);

        StateMachineInitializer mockStateMachineInitializer = mock(StateMachineInitializer.class);
        when(mockStateMachineInitializer.initialize())
                .thenReturn(
                        Map.of(
                                "STATE_ONE",
                                stateOne,
                                "STATE_TWO_NESTED_INVOKE_STATE",
                                stateTwo,
                                "STATE_THREE",
                                stateThree));

        StateMachine stateMachine = new StateMachine(mockStateMachineInitializer);

        assertEquals(
                doublyNestedStateTwo,
                stateMachine.getState(
                        "STATE_TWO_NESTED_INVOKE_STATE/NESTED_THREE_NESTED_INVOKE_STATE/DOUBLE_NESTED_TWO"));
    }

    @Test
    void isPageStateShouldReturnTrue() throws Exception {
        var stateWithPageResponse = mock(BasicState.class);
        when(stateWithPageResponse.getResponse()).thenReturn(new PageStepResponse());

        StateMachineInitializer mockStateMachineInitializer = mock(StateMachineInitializer.class);
        when(mockStateMachineInitializer.initialize())
                .thenReturn(Map.of("STATE_ONE", stateWithPageResponse));

        StateMachine stateMachine = new StateMachine(mockStateMachineInitializer);

        assertTrue(
                stateMachine.isPageState(new JourneyState(INITIAL_JOURNEY_SELECTION, "STATE_ONE")));
    }

    @Test
    void isPageStateShouldReturnFalseIfNotPageResponse() throws Exception {
        var stateWithProcessResponse = mock(BasicState.class);
        when(stateWithProcessResponse.getResponse()).thenReturn(new ProcessStepResponse());

        StateMachineInitializer mockStateMachineInitializer = mock(StateMachineInitializer.class);
        when(mockStateMachineInitializer.initialize())
                .thenReturn(Map.of("STATE_ONE", stateWithProcessResponse));

        StateMachine stateMachine = new StateMachine(mockStateMachineInitializer);

        assertFalse(
                stateMachine.isPageState(new JourneyState(INITIAL_JOURNEY_SELECTION, "STATE_ONE")));
    }

    @Test
    void isPageStateShouldReturnFalseIfNotBasicState() throws Exception {
        var nestedJourneyInvokeState = mock(NestedJourneyInvokeState.class);

        StateMachineInitializer mockStateMachineInitializer = mock(StateMachineInitializer.class);
        when(mockStateMachineInitializer.initialize())
                .thenReturn(Map.of("STATE_ONE", nestedJourneyInvokeState));

        StateMachine stateMachine = new StateMachine(mockStateMachineInitializer);

        assertFalse(
                stateMachine.isPageState(new JourneyState(INITIAL_JOURNEY_SELECTION, "STATE_ONE")));
    }

    @Test
    void isPageStateShouldThrowIfNoStateFound() throws Exception {
        var nestedJourneyInvokeState = mock(NestedJourneyInvokeState.class);

        StateMachineInitializer mockStateMachineInitializer = mock(StateMachineInitializer.class);
        when(mockStateMachineInitializer.initialize())
                .thenReturn(Map.of("STATE_ONE", nestedJourneyInvokeState));

        StateMachine stateMachine = new StateMachine(mockStateMachineInitializer);

        assertThrows(
                UnknownStateException.class,
                () ->
                        stateMachine.isPageState(
                                new JourneyState(INITIAL_JOURNEY_SELECTION, "NO_STATE")));
    }
}
