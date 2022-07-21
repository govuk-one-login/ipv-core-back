package uk.gov.di.ipv.core.statemachine;

public class TransitionResponse {

    private final State state;
    private final String journeyResponse;

    public TransitionResponse(State state, String journeyResponse){
        this.state = state;
        this.journeyResponse = journeyResponse;
    }

    public State getState() {
        return state;
    }

    public String getJourneyResponse() {
        return journeyResponse;
    }
}
