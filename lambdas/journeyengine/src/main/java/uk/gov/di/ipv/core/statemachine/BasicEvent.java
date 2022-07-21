package uk.gov.di.ipv.core.statemachine;

public class BasicEvent implements Event{

    private String name;
    private State targetState;
    private JourneyStepResponse response;

    public BasicEvent(String name, State targetState, JourneyStepResponse response){
        this.name = name;
        this.targetState = targetState;
        this.response = response;
    }

    public StateMachineResult resolve(Context context){
        return new StateMachineResult(targetState, response);
    }

    public String getName() {
        return name;
    }
}
