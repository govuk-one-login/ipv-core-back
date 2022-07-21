package uk.gov.di.ipv.core.statemachine;

public class JourneyResponse implements JourneyStepResponse{

    private final String journeyStepId;

    public JourneyResponse(String journeyStepId){
        this.journeyStepId = journeyStepId;
    }

    public String value(){
        return String.format("\"journey\":\"%s\"", journeyStepId);
    }
}
