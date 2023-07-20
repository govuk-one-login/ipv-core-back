package uk.gov.di.ipv.core.processjourneystep.statemachine;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import uk.gov.di.ipv.core.processjourneystep.statemachine.exceptions.UnknownEventException;
import uk.gov.di.ipv.core.processjourneystep.statemachine.exceptions.UnknownStateException;
import uk.gov.di.ipv.core.processjourneystep.statemachine.responses.JourneyContext;
import uk.gov.di.ipv.core.processjourneystep.statemachine.states.State;
import uk.gov.di.ipv.core.processjourneystep.statemachine.states.SubJourneyInvokeState;

import java.io.IOException;
import java.util.Map;

public class StateMachine {
    private static final Logger LOGGER = LogManager.getLogger();

    private final Map<String, State> states;

    public StateMachine(StateMachineInitializer initializer) throws IOException {
        this.states = initializer.initialize();
    }

    public State transition(String startState, String event, JourneyContext journeyContext)
            throws UnknownEventException, UnknownStateException {
        String firstPart = startState.split("/")[0];
        LOGGER.debug("firstPart: '{}'", firstPart);
        var state = states.get(firstPart);

        if (state == null) {
            throw new UnknownStateException(
                    String.format("Unknown state provided to state machine: %s", startState));
        }

        State newState = state.transition(event, startState, journeyContext);
        LOGGER.debug("newState: '{}'", newState);
        if (newState instanceof SubJourneyInvokeState) {
            LOGGER.debug("newState instanceof SubJourneyInvokeState");
            return newState.transition(event, startState, journeyContext);
        }
        return newState;
    }
}
