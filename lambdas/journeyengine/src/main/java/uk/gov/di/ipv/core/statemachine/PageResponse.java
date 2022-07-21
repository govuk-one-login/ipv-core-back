package uk.gov.di.ipv.core.statemachine;

public class PageResponse implements JourneyStepResponse{

    private final String pageId;

    public PageResponse(String pageId){
        this.pageId = pageId;
    }

    public String value(){
        return String.format("\"page\":\"%s\"", pageId);
    }
}
