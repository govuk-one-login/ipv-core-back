package uk.gov.di.ipv.core.processjourneyevent.statemachine.states;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.TransitionResult;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.events.BasicEvent;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.events.EventResolveParameters;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.events.EventResolver;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.exceptions.UnknownEventException;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.exceptions.UnknownStateException;

import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class NestedJourneyInvokeStateTest {
    private static final EventResolveParameters EVENT_RESOLVE_PARAMETERS =
            new EventResolveParameters(
                    List.of("journeyContext"), new IpvSessionItem(), new ClientOAuthSessionItem());
    @Mock private EventResolver eventResolver;

    @Test
    void transitionShouldUseEntryEventsWhenStartStateHasOnePart() throws Exception {
        var expectedResult = new TransitionResult(new BasicState());
        BasicEvent basicEvent = mock(BasicEvent.class);
        when(eventResolver.resolve(eq(basicEvent), any(EventResolveParameters.class)))
                .thenReturn(expectedResult);

        NestedJourneyDefinition nestedJourneyDefinition = new NestedJourneyDefinition();
        nestedJourneyDefinition.setEntryEvents(Map.of("next", basicEvent));

        NestedJourneyInvokeState nestedJourneyInvokeState = new NestedJourneyInvokeState();
        nestedJourneyInvokeState.setNestedJourneyDefinition(nestedJourneyDefinition);

        var actualResult =
                nestedJourneyInvokeState.transition(
                        "next", "INVOKE_STATE", EVENT_RESOLVE_PARAMETERS, eventResolver);

        assertEquals(expectedResult, actualResult);
    }

    @Test
    void transitionShouldReturnStateFromNestedJourneyDefinitionIfStartStateHasMultipleParts()
            throws Exception {
        NestedJourneyDefinition nestedJourneyDefinition = new NestedJourneyDefinition();
        BasicState currentNestedState = mock(BasicState.class);
        nestedJourneyDefinition.setNestedJourneyStates(Map.of("NESTED_STATE", currentNestedState));

        var expectedResult = new TransitionResult(new BasicState());
        when(currentNestedState.transition(
                        eq("next"),
                        eq("NESTED_STATE"),
                        any(EventResolveParameters.class),
                        eq(eventResolver)))
                .thenReturn(expectedResult);

        NestedJourneyInvokeState nestedJourneyInvokeState = new NestedJourneyInvokeState();
        nestedJourneyInvokeState.setNestedJourneyDefinition(nestedJourneyDefinition);

        var actualResult =
                nestedJourneyInvokeState.transition(
                        "next",
                        "INVOKE_STATE/NESTED_STATE",
                        EVENT_RESOLVE_PARAMETERS,
                        eventResolver);

        assertEquals(expectedResult, actualResult);
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
        var expectedResult = new TransitionResult(new BasicState());
        when(nestedNestedJourneyInvokeState.transition(
                        eq("next"),
                        eq("NESTED_STATE"),
                        any(EventResolveParameters.class),
                        eq(eventResolver)))
                .thenReturn(expectedResult);
        when(currentNestedState.transition(
                        eq("next"),
                        eq("NESTED_STATE"),
                        any(EventResolveParameters.class),
                        eq(eventResolver)))
                .thenReturn(new TransitionResult(nestedNestedJourneyInvokeState));

        var actualResult =
                nestedJourneyInvokeState.transition(
                        "next",
                        "INVOKE_STATE/NESTED_STATE",
                        EVENT_RESOLVE_PARAMETERS,
                        eventResolver);

        assertEquals(expectedResult, actualResult);
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
                                "unknown",
                                "INVOKE_STATE",
                                EVENT_RESOLVE_PARAMETERS,
                                eventResolver));
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
                                EVENT_RESOLVE_PARAMETERS,
                                eventResolver));
    }

    @Test
    void toStringShouldReturnStateName() {
        NestedJourneyInvokeState nestedJourneyInvokeState = new NestedJourneyInvokeState();
        nestedJourneyInvokeState.setName("Robert Paulsen");

        assertEquals("Robert Paulsen", nestedJourneyInvokeState.getName());
    }
}
