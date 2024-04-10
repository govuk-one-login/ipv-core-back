package uk.gov.di.ipv.core.processjourneyevent.statemachine;

import uk.gov.di.ipv.core.processjourneyevent.statemachine.exceptions.UnknownEventException;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.exceptions.UnknownStateException;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.states.BasicState;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.states.NestedJourneyInvokeState;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.states.State;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.stepresponses.CriStepResponse;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.stepresponses.JourneyContext;
import uk.gov.di.ipv.core.processjourneyevent.statemachine.stepresponses.PageStepResponse;

import java.io.IOException;
import java.util.Map;

public class StateMachine {
    public static final String DELIMITER = "/";
    private final Map<String, State> states;

    public StateMachine(StateMachineInitializer initializer) throws IOException {
        this.states = initializer.initialize();
    }

    public State transition(
            String startState, String event, JourneyContext journeyContext, String currentPage)
            throws UnknownEventException, UnknownStateException {
        var state = states.get(startState.split(DELIMITER)[0]);

        if (state == null) {
            throw new UnknownStateException(
                    String.format("Unknown state provided to state machine: %s", startState));
        }

        if (currentPage != null) {
            if (state instanceof BasicState basicState) {
                if (basicState.getResponse() instanceof PageStepResponse pageStepResponse) {
                    if (!pageStepResponse.getPageId().equals(currentPage)) {
                        return state;
                    }
                } else if (basicState.getResponse() instanceof CriStepResponse criStepResponse) {
                    if (!criStepResponse.getCriId().equals(currentPage)) {
                        return state;
                    }
                } else {
                    throw new UnknownStateException(
                            String.format(
                                    "Unknown state provided to state machine: %s", startState));
                }
            }
        }

        State newState = state.transition(event, startState, journeyContext);
        if (newState instanceof NestedJourneyInvokeState) {
            return newState.transition(event, startState, journeyContext);
        }

        return newState;
    }
}
