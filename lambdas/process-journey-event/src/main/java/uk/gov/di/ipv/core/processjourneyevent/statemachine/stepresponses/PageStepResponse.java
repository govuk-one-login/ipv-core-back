package uk.gov.di.ipv.core.processjourneyevent.statemachine.stepresponses;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.util.HashMap;
import java.util.Map;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class PageStepResponse implements StepResponse {

    private String pageId;
    private String context;
    @Getter private Boolean mitigationStart;

    public Map<String, Object> value() {
        Map<String, Object> response = new HashMap<>();
        response.put("page", pageId);
        response.put("context", context);

        return response;
    }
}
