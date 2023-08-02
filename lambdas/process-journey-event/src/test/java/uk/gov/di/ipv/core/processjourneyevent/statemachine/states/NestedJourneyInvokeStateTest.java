package uk.gov.di.ipv.core.processjourneyevent.statemachine.states;

import org.junit.jupiter.api.Test;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.events.BasicEvent;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.exceptions.UnknownEventException;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.exceptions.UnknownStateException;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.stepresponses.JourneyContext;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class NestedJourneyInvokeStateTest {
    @Test
    void transitionShouldUseEntryEventsWhenStartStateHasOnePart() throws Exception {
        BasicState expectedEndState = new BasicState();
        BasicEvent basicEvent = mock(BasicEvent.class);
        when(basicEvent.resolve(any(JourneyContext.class))).thenReturn(expectedEndState);

        NestedJourneyDefinition nestedJourneyDefinition = new NestedJourneyDefinition();
        nestedJourneyDefinition.setEntryEvents(Map.of("next", basicEvent));

        NestedJourneyInvokeState nestedJourneyInvokeState = new NestedJourneyInvokeState();
        nestedJourneyInvokeState.setNestedJourneyDefinition(nestedJourneyDefinition);

        State transitionedToState =
                nestedJourneyInvokeState.transition(
                        "next", "INVOKE_STATE", JourneyContext.emptyContext());

        assertEquals(expectedEndState, transitionedToState);
    }

    @Test
    void transitionShouldReturnStateFromNestedJourneyDefinitionIfStartStateHasMultipleParts()
            throws Exception {
        NestedJourneyDefinition nestedJourneyDefinition = new NestedJourneyDefinition();
        BasicState currentNestedState = mock(BasicState.class);
        nestedJourneyDefinition.setNestedJourneyStates(Map.of("NESTED_STATE", currentNestedState));

        BasicState expectedEndState = new BasicState();
        when(currentNestedState.transition(
                        eq("next"), eq("NESTED_STATE"), any(JourneyContext.class)))
                .thenReturn(expectedEndState);

        NestedJourneyInvokeState nestedJourneyInvokeState = new NestedJourneyInvokeState();
        nestedJourneyInvokeState.setNestedJourneyDefinition(nestedJourneyDefinition);

        State transitionedToState =
                nestedJourneyInvokeState.transition(
                        "next", "INVOKE_STATE/NESTED_STATE", JourneyContext.emptyContext());

        assertEquals(expectedEndState, transitionedToState);
    }

    @Test
    void transitionShouldHandleANestedNestedJourneyInvokeState() throws Exception {
        NestedJourneyDefinition nestedJourneyDefinition = new NestedJourneyDefinition();
        BasicState currentNestedState = mock(BasicState.class);
        nestedJourneyDefinition.setNestedJourneyStates(Map.of("NESTED_STATE", currentNestedState));

        NestedJourneyInvokeState nestedJourneyInvokeState = new NestedJourneyInvokeState();
        nestedJourneyInvokeState.setNestedJourneyDefinition(nestedJourneyDefinition);

        NestedJourneyInvokeState nestedNestedJourneyInvokeState =
                mock(NestedJourneyInvokeState.class);
        BasicState expectedEndState = new BasicState();
        when(nestedNestedJourneyInvokeState.transition(
                        eq("next"), eq("NESTED_STATE"), any(JourneyContext.class)))
                .thenReturn(expectedEndState);
        when(currentNestedState.transition(
                        eq("next"), eq("NESTED_STATE"), any(JourneyContext.class)))
                .thenReturn(nestedNestedJourneyInvokeState);

        State transitionedToState =
                nestedJourneyInvokeState.transition(
                        "next", "INVOKE_STATE/NESTED_STATE", JourneyContext.emptyContext());

        assertEquals(expectedEndState, transitionedToState);
    }

    @Test
    void transitionShouldThrowIfUnknownEntryEvent() {
        NestedJourneyDefinition nestedJourneyDefinition = new NestedJourneyDefinition();
        nestedJourneyDefinition.setEntryEvents(Map.of("next", mock(BasicEvent.class)));

        NestedJourneyInvokeState nestedJourneyInvokeState = new NestedJourneyInvokeState();
        nestedJourneyInvokeState.setNestedJourneyDefinition(nestedJourneyDefinition);

        assertThrows(
                UnknownEventException.class,
                () ->
                        nestedJourneyInvokeState.transition(
                                "unknown", "INVOKE_STATE", JourneyContext.emptyContext()));
    }

    @Test
    void transitionShouldThrowIfNestedStateNotFoundInDefinition() {
        NestedJourneyDefinition nestedJourneyDefinition = new NestedJourneyDefinition();
        BasicState currentNestedState = mock(BasicState.class);
        nestedJourneyDefinition.setNestedJourneyStates(Map.of("NESTED_STATE", currentNestedState));

        NestedJourneyInvokeState nestedJourneyInvokeState = new NestedJourneyInvokeState();
        nestedJourneyInvokeState.setNestedJourneyDefinition(nestedJourneyDefinition);

        assertThrows(
                UnknownStateException.class,
                () ->
                        nestedJourneyInvokeState.transition(
                                "unknown",
                                "INVOKE_STATE/UNKNOWN_STATE",
                                JourneyContext.emptyContext()));
    }

    @Test
    void toStringShouldReturnStateName() {
        NestedJourneyInvokeState nestedJourneyInvokeState = new NestedJourneyInvokeState();
        nestedJourneyInvokeState.setName("Robert Paulsen");

        assertEquals("Robert Paulsen", nestedJourneyInvokeState.getName());
    }
}
