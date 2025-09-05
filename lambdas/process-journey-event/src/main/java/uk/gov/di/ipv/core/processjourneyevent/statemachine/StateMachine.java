package uk.gov.di.ipv.core.processjourneyevent.statemachine;

import uk.gov.di.ipv.core.library.domain.JourneyState;
import uk.gov.di.ipv.core.processjourneyevent.exceptions.JourneyEngineException;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.events.EventResolveParameters;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.events.EventResolver;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.exceptions.UnknownEventException;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.exceptions.UnknownStateException;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.states.BasicState;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.states.NestedJourneyInvokeState;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.states.State;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.stepresponses.CriStepResponse;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.stepresponses.PageStepResponse;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.stepresponses.ProcessStepResponse;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import static java.util.Objects.requireNonNullElse;
import static uk.gov.di.ipv.core.library.collections.Merging.mergeLists;
import static uk.gov.di.ipv.core.library.collections.Merging.mergeMaps;
import static uk.gov.di.ipv.core.library.collections.Merging.mergeSets;
import static uk.gov.di.ipv.core.library.domain.JourneyState.JOURNEY_STATE_DELIMITER;

public class StateMachine {

    private final Map<String, State> states;

    public StateMachine(StateMachineInitializer initializer) throws IOException {
        this.states = initializer.initialize();
    }

    public TransitionResult transition(
            String startState,
            String event,
            String currentPage,
            EventResolveParameters eventResolveParameters,
            EventResolver eventResolver)
            throws UnknownEventException, UnknownStateException, JourneyEngineException {
        var state = states.get(startState.split(JOURNEY_STATE_DELIMITER)[0]);

        if (state == null) {
            throw new UnknownStateException(
                    String.format("Unknown state provided to state machine: %s", startState));
        }

        // Check page event is allowed
        var leafState = getState(startState);
        if (currentPage != null && leafState instanceof BasicState basicState) {
            if (isPageOrCriStateAndOutOfSync(basicState, currentPage)) {
                return new TransitionResult(leafState);
            } else if (basicState.getResponse() instanceof ProcessStepResponse) {
                throw new UnknownStateException(
                        String.format(
                                "Unexpected page event (%s) from page (%s) received in process state (%s)",
                                event, currentPage, startState));
            }
        }

        var result = state.transition(event, startState, eventResolveParameters, eventResolver);

        // Resolve nested journey
        if (result.state() instanceof NestedJourneyInvokeState) {
            var entryEvent = requireNonNullElse(result.targetEntryEvent(), event);
            var nestedResult =
                    result.state()
                            .transition(
                                    entryEvent, startState, eventResolveParameters, eventResolver);
            // Add audit events and context from the outer event
            return new TransitionResult(
                    nestedResult.state(),
                    mergeLists(result.auditEvents(), nestedResult.auditEvents()),
                    mergeMaps(result.auditContext(), nestedResult.auditContext()),
                    nestedResult.targetEntryEvent(),
                    mergeSets(result.journeyContextsToSet(), nestedResult.journeyContextsToSet()),
                    mergeSets(
                            result.journeyContextsToUnset(),
                            nestedResult.journeyContextsToUnset()));
        }

        return result;
    }

    public boolean isPageState(JourneyState journeyState) throws UnknownStateException {
        var state = getState(journeyState.state());
        if (state == null) {
            throw new UnknownStateException(
                    String.format(
                            "Unknown state provided. State machine: '%s', state: '%s'",
                            journeyState.subJourney(), journeyState.state()));
        }
        return state instanceof BasicState basicState
                && basicState.getResponse() instanceof PageStepResponse;
    }

    public State getState(String state) {
        return recurseToState(
                states, new ArrayList<>(Arrays.asList(state.split(JOURNEY_STATE_DELIMITER))));
    }

    private State recurseToState(Map<String, State> statesMap, List<String> stateParts) {
        if (stateParts.size() == 1) {
            return statesMap.get(stateParts.get(0));
        } else {
            // Recurse into nested states to find the actual state we care about
            return recurseToState(
                    ((NestedJourneyInvokeState) statesMap.get(stateParts.remove(0)))
                            .getNestedJourneyDefinition()
                            .getNestedJourneyStates(),
                    stateParts);
        }
    }

    private boolean isPageOrCriStateAndOutOfSync(BasicState basicState, String currentPage) {
        return basicState.getResponse() instanceof PageStepResponse pageStepResponse
                        && !pageStepResponse.getPageId().equals(currentPage)
                || basicState.getResponse() instanceof CriStepResponse;
    }
}
