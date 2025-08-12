package uk.gov.di.ipv.core.processjourneyevent.statemachine;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import uk.gov.di.ipv.core.library.auditing.AuditEventTypes;
import uk.gov.di.ipv.core.library.domain.JourneyState;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.events.EventResolveParameters;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.events.EventResolver;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.exceptions.UnknownStateException;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.states.BasicState;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.states.NestedJourneyDefinition;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.states.NestedJourneyInvokeState;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.states.State;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.stepresponses.PageStepResponse;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.stepresponses.ProcessStepResponse;

import java.util.Arrays;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static uk.gov.di.ipv.core.library.domain.IpvJourneyTypes.INITIAL_JOURNEY_SELECTION;

class StateMachineTest {
    private static final EventResolveParameters EVENT_RESOLVE_PARAMETERS =
            new EventResolveParameters(
                    "journeyContext", new IpvSessionItem(), new ClientOAuthSessionItem());
    @Mock private EventResolver eventResolver;

    @Test
    void transitionShouldReturnAppropriateState() throws Exception {
        var expectedResult = new TransitionResult(new BasicState());

        State startingState = mock(BasicState.class);
        when(startingState.transition(
                        "event", "START_STATE", EVENT_RESOLVE_PARAMETERS, eventResolver))
                .thenReturn(expectedResult);

        StateMachineInitializer mockStateMachineInitializer = mock(StateMachineInitializer.class);
        when(mockStateMachineInitializer.initialize())
                .thenReturn(Map.of("START_STATE", startingState));

        StateMachine stateMachine = new StateMachine(mockStateMachineInitializer);

        var actualResult =
                stateMachine.transition(
                        "START_STATE", "event", null, EVENT_RESOLVE_PARAMETERS, eventResolver);

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
                () ->
                        stateMachine.transition(
                                "UNKNOWN_STATE",
                                "event",
                                null,
                                EVENT_RESOLVE_PARAMETERS,
                                eventResolver));
    }

    @Test
    void transitionShouldTransitionIntoNestedJourneyInvokeState() throws Exception {
        var expectedResult = new TransitionResult(new BasicState());
        State nestedJourneyInvokeState = mock(NestedJourneyInvokeState.class);
        when(nestedJourneyInvokeState.transition(
                        "event", "START_STATE", EVENT_RESOLVE_PARAMETERS, eventResolver))
                .thenReturn(expectedResult);

        State startingState = mock(BasicState.class);
        when(startingState.transition(
                        "event", "START_STATE", EVENT_RESOLVE_PARAMETERS, eventResolver))
                .thenReturn(new TransitionResult(nestedJourneyInvokeState));

        StateMachineInitializer mockStateMachineInitializer = mock(StateMachineInitializer.class);
        when(mockStateMachineInitializer.initialize())
                .thenReturn(Map.of("START_STATE", startingState));

        StateMachine stateMachine = new StateMachine(mockStateMachineInitializer);

        var actualResult =
                stateMachine.transition(
                        "START_STATE", "event", null, EVENT_RESOLVE_PARAMETERS, eventResolver);

        assertEquals(expectedResult, actualResult);
    }

    @Test
    void transitionShouldPreserveAuditEventsAndContextFromFirstTransitionIntoNestedJourney()
            throws Exception {
        // Arrange
        var nestedResult = new TransitionResult(new BasicState());
        State nestedJourneyInvokeState = mock(NestedJourneyInvokeState.class);
        when(nestedJourneyInvokeState.transition(
                        "event", "START_STATE", EVENT_RESOLVE_PARAMETERS, eventResolver))
                .thenReturn(nestedResult);

        State startingState = mock(BasicState.class);
        when(startingState.transition(
                        "event", "START_STATE", EVENT_RESOLVE_PARAMETERS, eventResolver))
                .thenReturn(
                        new TransitionResult(
                                nestedJourneyInvokeState,
                                Arrays.asList(AuditEventTypes.IPV_USER_DETAILS_UPDATE_START),
                                Map.of("testKey", "testValue"),
                                null));

        StateMachineInitializer mockStateMachineInitializer = mock(StateMachineInitializer.class);
        when(mockStateMachineInitializer.initialize())
                .thenReturn(Map.of("START_STATE", startingState));

        StateMachine stateMachine = new StateMachine(mockStateMachineInitializer);

        // Act
        var actualResult =
                stateMachine.transition(
                        "START_STATE", "event", null, EVENT_RESOLVE_PARAMETERS, eventResolver);

        // Assert
        var expectedResult =
                new TransitionResult(
                        new BasicState(),
                        Arrays.asList(AuditEventTypes.IPV_USER_DETAILS_UPDATE_START),
                        Map.of("testKey", "testValue"),
                        null);
        assertEquals(expectedResult, actualResult);
    }

    @Test
    void transitionShouldPreserveAuditEventsAndContextFromSecondTransitionIntoNestedJourney()
            throws Exception {
        // Arrange
        var nestedResult =
                new TransitionResult(
                        new BasicState(),
                        Arrays.asList(AuditEventTypes.IPV_USER_DETAILS_UPDATE_START),
                        Map.of("testKey", "testValue"),
                        null);
        State nestedJourneyInvokeState = mock(NestedJourneyInvokeState.class);
        when(nestedJourneyInvokeState.transition(
                        "event", "START_STATE", EVENT_RESOLVE_PARAMETERS, eventResolver))
                .thenReturn(nestedResult);

        State startingState = mock(BasicState.class);
        when(startingState.transition(
                        "event", "START_STATE", EVENT_RESOLVE_PARAMETERS, eventResolver))
                .thenReturn(new TransitionResult(nestedJourneyInvokeState));

        StateMachineInitializer mockStateMachineInitializer = mock(StateMachineInitializer.class);
        when(mockStateMachineInitializer.initialize())
                .thenReturn(Map.of("START_STATE", startingState));

        StateMachine stateMachine = new StateMachine(mockStateMachineInitializer);

        // Act
        var actualResult =
                stateMachine.transition(
                        "START_STATE", "event", null, EVENT_RESOLVE_PARAMETERS, eventResolver);

        // Assert
        var expectedResult =
                new TransitionResult(
                        new BasicState(),
                        Arrays.asList(AuditEventTypes.IPV_USER_DETAILS_UPDATE_START),
                        Map.of("testKey", "testValue"),
                        null);
        assertEquals(expectedResult, actualResult);
    }

    @Test
    void transitionShouldCombineAuditEventsAndContextFromFirstAndSecondTransitionIntoNestedJourney()
            throws Exception {
        // Arrange
        var nestedResult =
                new TransitionResult(
                        new BasicState(),
                        Arrays.asList(AuditEventTypes.IPV_USER_DETAILS_UPDATE_START),
                        Map.of("testKey1", "testValue1"),
                        null);
        State nestedJourneyInvokeState = mock(NestedJourneyInvokeState.class);
        when(nestedJourneyInvokeState.transition(
                        "event", "START_STATE", EVENT_RESOLVE_PARAMETERS, eventResolver))
                .thenReturn(nestedResult);

        State startingState = mock(BasicState.class);
        when(startingState.transition(
                        "event", "START_STATE", EVENT_RESOLVE_PARAMETERS, eventResolver))
                .thenReturn(
                        new TransitionResult(
                                nestedJourneyInvokeState,
                                Arrays.asList(AuditEventTypes.IPV_ACCOUNT_INTERVENTION_START),
                                Map.of("testKey2", "testValue2"),
                                null));

        StateMachineInitializer mockStateMachineInitializer = mock(StateMachineInitializer.class);
        when(mockStateMachineInitializer.initialize())
                .thenReturn(Map.of("START_STATE", startingState));

        StateMachine stateMachine = new StateMachine(mockStateMachineInitializer);

        // Act
        var actualResult =
                stateMachine.transition(
                        "START_STATE", "event", null, EVENT_RESOLVE_PARAMETERS, eventResolver);

        // Assert
        var expectedResult =
                new TransitionResult(
                        new BasicState(),
                        Arrays.asList(
                                AuditEventTypes.IPV_ACCOUNT_INTERVENTION_START,
                                AuditEventTypes.IPV_USER_DETAILS_UPDATE_START),
                        Map.of("testKey1", "testValue1", "testKey2", "testValue2"),
                        null);
        assertEquals(expectedResult, actualResult);
    }

    @Test
    void transitionShouldTransitionIntoNestedJourneyInvokeStateWithEntryEventOverride()
            throws Exception {
        var event = "event";
        var eventOverride = "eventOverride";

        // Nested event transitions using the override
        var expectedResult = new TransitionResult(new BasicState());
        State nestedJourneyInvokeState = mock(NestedJourneyInvokeState.class);
        when(nestedJourneyInvokeState.transition(
                        eventOverride, "START_STATE", EVENT_RESOLVE_PARAMETERS, eventResolver))
                .thenReturn(expectedResult);

        // Outer event transitions using the overall event
        State startingState = mock(BasicState.class);
        when(startingState.transition(
                        event, "START_STATE", EVENT_RESOLVE_PARAMETERS, eventResolver))
                .thenReturn(
                        new TransitionResult(nestedJourneyInvokeState, null, null, eventOverride));

        StateMachineInitializer mockStateMachineInitializer = mock(StateMachineInitializer.class);
        when(mockStateMachineInitializer.initialize())
                .thenReturn(Map.of("START_STATE", startingState));

        StateMachine stateMachine = new StateMachine(mockStateMachineInitializer);

        var actualResult =
                stateMachine.transition(
                        "START_STATE", event, null, EVENT_RESOLVE_PARAMETERS, eventResolver);

        assertEquals(expectedResult, actualResult);
    }

    @Test
    void transitionShouldHandleNestedStateName() throws Exception {
        var expectedResult = new TransitionResult(new BasicState());

        var startingState = mock(NestedJourneyInvokeState.class);
        var nestedJourneyDefinition = mock(NestedJourneyDefinition.class);
        when(startingState.getNestedJourneyDefinition()).thenReturn(
                nestedJourneyDefinition
        );
        when(nestedJourneyDefinition.getNestedJourneyStates()).thenReturn(
                Map.of("NESTED_JOURNEY", new BasicState())
        );
        when(startingState.transition(
                        "event",
                        "START_STATE/NESTED_JOURNEY",
                        EVENT_RESOLVE_PARAMETERS,
                        eventResolver))
                .thenReturn(expectedResult);

        var mockStateMachineInitializer = mock(StateMachineInitializer.class);
        when(mockStateMachineInitializer.initialize())
                .thenReturn(Map.of("START_STATE", startingState));

        var stateMachine = new StateMachine(mockStateMachineInitializer);

        var actualResult =
                stateMachine.transition(
                        "START_STATE/NESTED_JOURNEY",
                        "event",
                        null,
                        EVENT_RESOLVE_PARAMETERS,
                        eventResolver);

        assertEquals(expectedResult, actualResult);
    }

    @Test
    void transitionShouldBeBlockedIfUnexpectedCurrentPage() throws Exception {
        // Arrange
        var startingState = mock(BasicState.class);
        when(startingState.getResponse()).thenReturn(new PageStepResponse("some-page", null, null));
        when(startingState.transition(
                "event",
                "START_STATE",
                EVENT_RESOLVE_PARAMETERS,
                eventResolver))
                .thenReturn(new TransitionResult(new BasicState()));

        var mockStateMachineInitializer = mock(StateMachineInitializer.class);
        when(mockStateMachineInitializer.initialize())
                .thenReturn(Map.of("START_STATE", startingState));
        var stateMachine = new StateMachine(mockStateMachineInitializer);

        // Act
        var result =
                stateMachine.transition(
                        "START_STATE",
                        "event",
                        "not-the-same-page",
                        EVENT_RESOLVE_PARAMETERS,
                        eventResolver);

        // Assert
        assertEquals(startingState, result.state());
    }

    @Test
    void transitionShouldBeBlockedIfUnexpectedCurrentPageInNestedState() throws Exception {
        var startingState = mock(NestedJourneyInvokeState.class);
        var nestedJourneyDefinition = mock(NestedJourneyDefinition.class);
        when(startingState.getNestedJourneyDefinition()).thenReturn(
                nestedJourneyDefinition
        );
        var startingBasicState = mock(BasicState.class);
        when(startingBasicState.getResponse()).thenReturn(new PageStepResponse("some-page", null, null));
        when(nestedJourneyDefinition.getNestedJourneyStates()).thenReturn(
                Map.of("NESTED_JOURNEY", startingBasicState)
        );
        when(startingState.transition(
                "event",
                "START_STATE/NESTED_JOURNEY",
                EVENT_RESOLVE_PARAMETERS,
                eventResolver))
                .thenReturn(new TransitionResult(new BasicState("Unreachable due to incorrect previous pageId", null, null, null, null, null, null)));

        var mockStateMachineInitializer = mock(StateMachineInitializer.class);
        when(mockStateMachineInitializer.initialize())
                .thenReturn(Map.of("START_STATE", startingState));

        var stateMachine = new StateMachine(mockStateMachineInitializer);

        // Act
        var result =
                stateMachine.transition(
                        "START_STATE/NESTED_JOURNEY",
                        "event",
                        "not-the-same-page",
                        EVENT_RESOLVE_PARAMETERS,
                        eventResolver);

        // Assert
        assertEquals(startingBasicState, result.state());
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
