package uk.gov.di.ipv.core.statemachine;

public class PageResponse implements JourneyStepResponse{

    private String pageId;

    public PageResponse() {}

    public PageResponse(String pageId){
        this.pageId = pageId;
    }

    public String getPageId() {
        return pageId;
    }

    public void setPageId(String pageId) {
        this.pageId = pageId;
    }

    public String value(){
        return String.format("\"page\":\"%s\"", pageId);
    }
}
