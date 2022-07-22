package uk.gov.di.ipv.core.statemachine;

public class JourneyResponse implements JourneyStepResponse{

    private String journeyStepId;

    public JourneyResponse() {}

    public JourneyResponse(String journeyStepId){
        this.journeyStepId = journeyStepId;
    }

    public String getJourneyStepId() {
        return journeyStepId;
    }

    public void setJourneyStepId(String journeyStepId) {
        this.journeyStepId = journeyStepId;
    }

    public String value(){
        return String.format("\"journey\":\"%s\"", journeyStepId);
    }
}
