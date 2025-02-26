package uk.gov.di.ipv.core.processjourneyevent.statemachine;

import uk.gov.di.ipv.core.library.domain.JourneyState;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.exceptions.UnknownEventException;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.exceptions.UnknownStateException;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.states.BasicState;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.states.NestedJourneyInvokeState;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.states.State;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.stepresponses.CriStepResponse;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.stepresponses.JourneyContext;
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
import static uk.gov.di.ipv.core.library.domain.JourneyState.JOURNEY_STATE_DELIMITER;

public class StateMachine {

    private final Map<String, State> states;

    public StateMachine(StateMachineInitializer initializer) throws IOException {
        this.states = initializer.initialize();
    }

    public TransitionResult transition(
            String startState, String event, JourneyContext journeyContext, String currentPage)
            throws UnknownEventException, UnknownStateException {
        var state = states.get(startState.split(JOURNEY_STATE_DELIMITER)[0]);

        if (state == null) {
            throw new UnknownStateException(
                    String.format("Unknown state provided to state machine: %s", startState));
        }

        // Check page event is allowed
        if (currentPage != null && state instanceof BasicState basicState) {
            if (isPageOrCriStateAndOutOfSync(basicState, currentPage)) {
                return new TransitionResult(state);
            } else if (basicState.getResponse() instanceof ProcessStepResponse) {
                throw new UnknownStateException(
                        String.format(
                                "Unexpected page event (%s) from page (%s) received in process state (%s)",
                                event, currentPage, startState));
            }
        }

        var result = state.transition(event, startState, journeyContext);

        // Resolve nested journey
        if (result.state() instanceof NestedJourneyInvokeState) {
            var entryEvent = requireNonNullElse(result.targetEntryEvent(), event);
            var nestedResult = result.state().transition(entryEvent, startState, journeyContext);
            // Add audit events and context from the outer event
            return new TransitionResult(
                    nestedResult.state(),
                    mergeLists(result.auditEvents(), nestedResult.auditEvents()),
                    mergeMaps(result.auditContext(), nestedResult.auditContext()),
                    nestedResult.targetEntryEvent());
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
