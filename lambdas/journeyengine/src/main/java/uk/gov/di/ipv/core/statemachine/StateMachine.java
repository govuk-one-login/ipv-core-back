package uk.gov.di.ipv.core.statemachine;

import java.util.HashMap;
import java.util.Map;

public class StateMachine {

    private State initialState;
    private Map<String, State> states = new HashMap<>();

    public StateMachine(StateMachineInitializer initializer){
        this.states = initializer.initialize();
    }

    public StateMachine withState(State state){
        states.put(state.getName(), state);
        return this;
    }

    public StateMachineResult transition(String startState, String event, Context context) throws UnknownEventException {
        var state =states.get(startState);
        return state.transition(event, context);
    }


}
