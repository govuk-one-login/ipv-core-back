package uk.gov.di.ipv.core.processjourneyevent.statemachine;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.ipv.core.library.helpers.LogHelper;
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
import java.util.Optional;

public class StateMachine {
    public static final String DELIMITER = "/";
    private final Map<String, State> states;

    private static final Logger LOGGER = LogManager.getLogger();

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

        if (currentPage.isPresent() && !currentPage.get().equals("oauth")) {
            if (state instanceof BasicState) {

                if (((BasicState) state).getResponse() instanceof PageStepResponse) {

                    String pageId = ((PageStepResponse) ((BasicState) state).getResponse()).getPageId();

                    if (!currentPage.get().equals(pageId)) {
                        LOGGER.warn(LogHelper.buildLogMessage(String.format("Something has gone wrong: %s, %s, %s", pageId, currentPage.get(), event)));
                        return state;
                    }
                } else if (((BasicState) state).getResponse() instanceof CriStepResponse) {
                    return state;
                } else {
                    throw new UnknownStateException(
                            String.format("Unknown state provided to state machine: %s", startState));
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
