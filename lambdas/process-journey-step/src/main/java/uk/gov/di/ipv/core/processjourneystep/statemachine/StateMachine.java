package uk.gov.di.ipv.core.processjourneystep.statemachine;

import uk.gov.di.ipv.core.processjourneystep.statemachine.exceptions.UnknownEventException;
import uk.gov.di.ipv.core.processjourneystep.statemachine.exceptions.UnknownStateException;
import uk.gov.di.ipv.core.processjourneystep.statemachine.responses.JourneyContext;

import java.io.IOException;
import java.util.Map;

public class StateMachine {

    private Map<String, State> states;

    public StateMachine(StateMachineInitializer initializer) throws IOException {
        this.states = initializer.initialize();
    }

    public StateMachineResult transition(
            String startState, String event, JourneyContext journeyContext)
            throws UnknownEventException, UnknownStateException {
        var state = states.get(startState);

        if (state == null) {
            throw new UnknownStateException(
                    String.format("Unknown state provided to state machine: %s", startState));
        }

        return state.transition(event, journeyContext);
    }
}
