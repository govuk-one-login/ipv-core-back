package uk.gov.di.ipv.core.processjourneyevent.statemachine.stepresponses;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.HashMap;
import java.util.Map;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class PageStepResponse implements StepResponse {

    private String pageId;
    private String context;
    private Boolean skipBack;

    public Map<String, Object> value() {
        Map<String, Object> response = new HashMap<>();
        response.put("page", pageId);
        response.put("context", context);
        response.put("skipBack", skipBack);

        return response;
    }
}
