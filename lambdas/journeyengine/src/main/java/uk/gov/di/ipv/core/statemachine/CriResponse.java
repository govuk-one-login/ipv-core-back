package uk.gov.di.ipv.core.statemachine;

public class CriResponse implements JourneyStepResponse{

    private final String criId;

    public CriResponse(String criId){
        this.criId = criId;
    }

    public String value(){
        return String.format("\"cri\":\"%s\"", criId);
    }
}
