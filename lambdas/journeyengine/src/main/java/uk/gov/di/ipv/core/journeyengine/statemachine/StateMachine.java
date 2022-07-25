package uk.gov.di.ipv.core.journeyengine.statemachine;

import uk.gov.di.ipv.core.journeyengine.statemachine.exceptions.UnknownEventException;
import uk.gov.di.ipv.core.journeyengine.statemachine.exceptions.UnknownStateException;
import uk.gov.di.ipv.core.journeyengine.statemachine.responses.Context;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

public class StateMachine {

    private Map<String, State> states = new HashMap<>();

    public StateMachine(StateMachineInitializer initializer) throws IOException {
        this.states = initializer.initialize();
    }

    public StateMachineResult transition(String startState, String event, Context context)
            throws UnknownEventException, UnknownStateException {
        var state = states.get(startState);

        if (state == null) {
            throw new UnknownStateException(
                    String.format("Unknown state provided to state machine: %s", startState));
        }

        return state.transition(event, context);
    }
}
