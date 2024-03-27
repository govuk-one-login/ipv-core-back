package uk.gov.di.ipv.core.processjourneyevent.statemachine;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.message.StringMapMessage;
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
import java.util.Map;
import java.util.Optional;

public class StateMachine {
    public static final String DELIMITER = "/";
    private final Map<String, State> states;

    public StateMachine(StateMachineInitializer initializer) throws IOException {
        this.states = initializer.initialize();
    }

    public State transition(
            String startState,
            String event,
            JourneyContext journeyContext,
            Optional<String> currentPage)
            throws UnknownEventException, UnknownStateException {
        var state = states.get(startState.split(DELIMITER)[0]);

        if (state == null) {
            throw new UnknownStateException(
                    String.format("Unknown state provided to state machine: %s", startState));
        }

        if (state instanceof BasicState && currentPage.isPresent()) {

            if (((BasicState) state).getResponse() instanceof PageStepResponse) {

                String pageId = ((PageStepResponse) ((BasicState) state).getResponse()).getPageId();

                if (!currentPage.get().equals(pageId)) {
                    return state;
                }
            } else if (((BasicState) state).getResponse() instanceof CriStepResponse) {
                String criId = ((CriStepResponse) ((BasicState) state).getResponse()).getCriId();

                if (!currentPage.get().equals(criId)) {
                    return state;
                }
            } else if (((BasicState) state).getResponse() instanceof ProcessStepResponse) {
                return state;
            }
        }

        State newState = state.transition(event, startState, journeyContext);
        if (newState instanceof NestedJourneyInvokeState) {
            return newState.transition(event, startState, journeyContext);
        }

        return newState;
    }
}
