package uk.gov.di.ipv.core.processjourneyevent.statemachine.states;

import org.junit.jupiter.api.Test;
import uk.gov.di.ipv.core.library.persistence.item.ClientOAuthSessionItem;
import uk.gov.di.ipv.core.library.persistence.item.IpvSessionItem;
import uk.gov.di.ipv.core.library.service.CimitUtilityService;
import uk.gov.di.ipv.core.library.service.ConfigService;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.TransitionResult;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.events.BasicEvent;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.events.EventResolveParameters;
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
    private static final JourneyContext JOURNEY_CONTEXT =
            new JourneyContext(mock(ConfigService.class), "");
    private static final EventResolveParameters EVENT_RESOLVE_PARAMETERS =
            new EventResolveParameters(
                    JOURNEY_CONTEXT,
                    new IpvSessionItem(),
                    new ClientOAuthSessionItem(),
                    new CimitUtilityService(mock(ConfigService.class)));

    @Test
    void transitionShouldUseEntryEventsWhenStartStateHasOnePart() throws Exception {
        var expectedResult = new TransitionResult(new BasicState());
        BasicEvent basicEvent = mock(BasicEvent.class);
        when(basicEvent.resolve(any(EventResolveParameters.class))).thenReturn(expectedResult);

        NestedJourneyDefinition nestedJourneyDefinition = new NestedJourneyDefinition();
        nestedJourneyDefinition.setEntryEvents(Map.of("next", basicEvent));

        NestedJourneyInvokeState nestedJourneyInvokeState = new NestedJourneyInvokeState();
        nestedJourneyInvokeState.setNestedJourneyDefinition(nestedJourneyDefinition);

        var actualResult =
                nestedJourneyInvokeState.transition(
                        "next", "INVOKE_STATE", EVENT_RESOLVE_PARAMETERS);

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
                        eq("next"), eq("NESTED_STATE"), any(EventResolveParameters.class)))
                .thenReturn(expectedResult);

        NestedJourneyInvokeState nestedJourneyInvokeState = new NestedJourneyInvokeState();
        nestedJourneyInvokeState.setNestedJourneyDefinition(nestedJourneyDefinition);

        var actualResult =
                nestedJourneyInvokeState.transition(
                        "next", "INVOKE_STATE/NESTED_STATE", EVENT_RESOLVE_PARAMETERS);

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
                        eq("next"), eq("NESTED_STATE"), any(EventResolveParameters.class)))
                .thenReturn(expectedResult);
        when(currentNestedState.transition(
                        eq("next"), eq("NESTED_STATE"), any(EventResolveParameters.class)))
                .thenReturn(new TransitionResult(nestedNestedJourneyInvokeState));

        var actualResult =
                nestedJourneyInvokeState.transition(
                        "next", "INVOKE_STATE/NESTED_STATE", EVENT_RESOLVE_PARAMETERS);

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
                                "unknown", "INVOKE_STATE", EVENT_RESOLVE_PARAMETERS));
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
                                "unknown", "INVOKE_STATE/UNKNOWN_STATE", EVENT_RESOLVE_PARAMETERS));
    }

    @Test
    void toStringShouldReturnStateName() {
        NestedJourneyInvokeState nestedJourneyInvokeState = new NestedJourneyInvokeState();
        nestedJourneyInvokeState.setName("Robert Paulsen");

        assertEquals("Robert Paulsen", nestedJourneyInvokeState.getName());
    }
}
