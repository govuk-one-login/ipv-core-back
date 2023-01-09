package uk.gov.di.ipv.core.processjourneystep.statemachine.responses;

import uk.gov.di.ipv.core.library.service.ConfigurationService;

import java.util.Map;

public class ErrorResponse implements JourneyStepResponse {

    public static final String ERROR = "error";
    private String pageId;
    private String httpStatusCode;

    public ErrorResponse() {}

    public ErrorResponse(String pageId, String httpStatusCode) {
        this.pageId = pageId;
        this.httpStatusCode = httpStatusCode;
    }

    public String getPageId() {
        return pageId;
    }

    public void setPageId(String pageId) {
        this.pageId = pageId;
    }

    public String getHttpStatusCode() {
        return httpStatusCode;
    }

    public void setHttpStatusCode(String httpStatusCode) {
        this.httpStatusCode = httpStatusCode;
    }

    public Map<String, Object> value(ConfigurationService configurationService) {
        return value(pageId);
    }

    public Map<String, Object> value(String id) {
        // TODO: Come up with a better way of converting httpsStatusCode to an Integer.
        return Map.of(
                "type",
                ERROR,
                "pageId",
                id,
                "httpStatusCode",
                httpStatusCode,
                "statusCode",
                Integer.parseInt(httpStatusCode));
    }
}
