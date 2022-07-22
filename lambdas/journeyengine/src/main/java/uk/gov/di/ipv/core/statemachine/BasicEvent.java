package uk.gov.di.ipv.core.statemachine;

public class BasicEvent implements Event {

    private String name;
    private State targetState;
    private JourneyStepResponse response;

    public BasicEvent() {}

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

    public void setName(String name) {
        this.name = name;
    }

    public State getTargetState() {
        return targetState;
    }

    public void setTargetState(State targetState) {
        this.targetState = targetState;
    }

    public JourneyStepResponse getResponse() {
        return response;
    }

    public void setResponse(JourneyStepResponse response) {
        this.response = response;
    }
}
