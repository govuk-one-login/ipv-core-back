package uk.gov.di.ipv.core.statemachine;

public class StateMachineResult {

    public final State state;
    public final JourneyStepResponse journeyStepResponse;

    public StateMachineResult(State state, JourneyStepResponse journeyStepResponse){
        this.state = state;
        this.journeyStepResponse = journeyStepResponse;
    }

    public State getState() {
        return state;
    }

    public JourneyStepResponse getJourneyStepResponse() {
        return journeyStepResponse;
    }
}
